package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func historyManagedInstallDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return t.TempDir()
	}
	if os.Geteuid() != 0 {
		t.Skip("strict managed installation requires root-owned directories; Bash behavior is separately tested without root")
	}
	dir, err := os.MkdirTemp("/run", "anquan-history-install-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestEnsureHistoryScriptInstallsMissingAndPreservesLog(t *testing.T) {
	dir := historyManagedInstallDir(t)
	script, log := filepath.Join(dir, "history-audit.sh"), filepath.Join(dir, "history.log")
	const existingLog = "existing retained command\n"
	if err := os.WriteFile(log, []byte(existingLog), 0644); err != nil {
		t.Fatal(err)
	}
	installed, err := ensureHistoryScriptAt(script, log, "/usr/local/agent with space/anquan")
	if err != nil || !installed {
		t.Fatalf("missing hook was not installed: %v %v", installed, err)
	}
	content, err := os.ReadFile(script)
	if err != nil || !bytes.Equal(content, managedHistoryScript("/usr/local/agent with space/anquan")) {
		t.Fatalf("installed hook differs from complete managed script: %v", err)
	}
	if !strings.Contains(string(content), "# anquan-managed-history-v1") || strings.Contains(string(content), "chmod") || strings.Contains(string(content), "HISTFILE=") || strings.Contains(string(content), "HISTSIZE=") {
		t.Fatal("managed hook marker or privilege boundary is incorrect")
	}
	info, err := os.Stat(script)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0644) || !verifyHistoryManagedOwner(info) {
		t.Fatalf("unsafe installed hook permissions/owner: %v %v", info, err)
	}
	if got, err := os.ReadFile(log); err != nil || string(got) != existingLog {
		t.Fatalf("installation changed existing log: %q %v", got, err)
	}
	before := info.ModTime()
	installed, err = ensureHistoryScriptAt(script, log, "/different binary")
	if err != nil || installed {
		t.Fatalf("repeated installation replaced existing hook: %v %v", installed, err)
	}
	info, _ = os.Stat(script)
	if !info.ModTime().Equal(before) {
		t.Fatal("repeated installation rewrote existing managed hook")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".anquan-history-install-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("installation left temporary scripts: %v %v", leftovers, err)
	}
}

func TestEnsureHistoryScriptPreservesCustomWriterAndState(t *testing.T) {
	dir := historyManagedInstallDir(t)
	c := historyTestConfig(t)
	c.History.Path = filepath.Join(dir, "history.log")
	put(t, c.History.Path, historyLine("already collected"))
	if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := read(t, c.StateFile+".commands")
	script := filepath.Join(dir, "history-audit.sh")
	const custom = "# custom administrator writer\nprintf '%s\\n' keep-custom\n"
	put(t, script, custom)
	if err := initializeHistoryManagedAt(c, nil, script, c.History.Path, "/usr/local/anquan/anquan"); err != nil {
		t.Fatal(err)
	}
	if read(t, script) != custom || read(t, c.StateFile+".commands") != before || read(t, c.History.Path) != historyLine("already collected") {
		t.Fatal("custom hook installation changed script, retained log or command cursor")
	}
	if readHistoryRecoveryState(t, c).ScriptRepair != nil || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("custom/missing script installation authorized history replay")
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := initializeHistoryManagedAt(c, nil, script, c.History.Path, "/usr/local/anquan/anquan"); err != nil {
		t.Fatal(err)
	}
	if read(t, c.StateFile+".commands") != before || readHistoryRecoveryState(t, c).ScriptRepair != nil || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("fresh hook installation reset cursor or created a recovery receipt")
	}
}

func TestEnsureHistoryScriptPreservesExternalLogPermissions(t *testing.T) {
	dir := historyManagedInstallDir(t)
	script, log := filepath.Join(dir, "history-audit.sh"), filepath.Join(dir, "history.log")
	if err := os.WriteFile(script, []byte("# administrator-owned external writer\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte("existing external record\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(log, 0666); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ensureHistoryScriptAt(script, log, historyCommandBinaryPath)
	if err != nil || installed || isManagedHistoryScript(script) {
		t.Fatalf("external writer was converted to managed logging: %t %v", installed, err)
	}
	after, err := os.Stat(log)
	if err != nil || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) || read(t, log) != "existing external record\n" {
		t.Fatalf("external log changed: %v", err)
	}
}

func TestEnsureHistoryScriptRejectsUnsafeTargetAndParent(t *testing.T) {
	dir := historyManagedInstallDir(t)
	log := filepath.Join(dir, "history.log")
	script := filepath.Join(dir, "history-audit.sh")
	if err := os.Mkdir(script, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryScriptAt(script, log, "/usr/local/anquan/anquan"); err == nil {
		t.Fatal("directory accepted as hook")
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(dir, "actual")
	put(t, actual, "retained")
	if err := os.Symlink(actual, script); err != nil {
		if runtime.GOOS == "windows" {
			t.Logf("symlink privilege unavailable: %v", err)
			return
		}
		t.Fatal(err)
	}
	if _, err := ensureHistoryScriptAt(script, log, "/usr/local/anquan/anquan"); err == nil || read(t, actual) != "retained" {
		t.Fatal("symlink hook was followed or replaced")
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "profile-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryScriptAt(filepath.Join(link, "history.sh"), log, "/usr/local/anquan/anquan"); err == nil {
		t.Fatal("symlink parent was accepted")
	}
}

func TestHistoryInstallationFailureIsReturnedAndDisabledUntouched(t *testing.T) {
	c := historyTestConfig(t)
	missing := filepath.Join(t.TempDir(), "missing-parent", "history.sh")
	if err := initializeHistoryManagedAt(c, nil, missing, c.History.Path, "/usr/local/anquan/anquan"); err == nil || !strings.Contains(err.Error(), "installation failed") {
		t.Fatalf("failed installation was hidden: %v", err)
	}
	c.History.Enabled = false
	if err := initializeHistoryManagedAt(c, nil, missing, c.History.Path, "/usr/local/anquan/anquan"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("disabled history installation touched parent: %v", err)
	}
	c.History.Enabled = true
	// Existing repair-only tests and callers must not install at host paths.
	if err := initializeHistoryScriptAt(c, nil, missing); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("repair-only initializer created missing script: %v", err)
	}
}
