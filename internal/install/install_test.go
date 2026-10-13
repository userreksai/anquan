package install

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func put(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func wantFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatalf("%s = %q, error %v; want %q", path, data, err, expected)
	}
}

func fixture(t *testing.T) (string, layout) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "usr", "local", "anquan")
	return filepath.Join(root, "upload", "renamed-agent"), layout{
		directory: directory, executable: filepath.Join(directory, "anquan"),
		script: filepath.Join(root, "usr", "local", "ssh-init.sh"), sshrc: filepath.Join(root, "etc", "ssh", "sshrc"),
		service: filepath.Join(root, "etc", "systemd", "system", ServiceName),
	}
}

func requireSymlinks(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("target", path); err != nil {
		t.Skipf("host does not permit symlink creation: %v", err)
	}
}

func TestInstallExecutableCopiesAndCanUpgradeWithoutTruncation(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "first binary")
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	if moved, err := installExecutable(source, paths.executable); err != nil || !moved {
		t.Fatalf("copy: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "first binary")
	put(t, source, "updated binary")
	if moved, err := installExecutable(source, paths.executable); err != nil || !moved {
		t.Fatalf("upgrade: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "updated binary")
	if moved, err := installExecutable(paths.executable, paths.executable); err != nil || moved {
		t.Fatalf("repeat: moved=%t err=%v", moved, err)
	}
	if _, err := installExecutable(filepath.Dir(source), paths.executable); err == nil {
		t.Fatal("directory accepted as executable")
	}
	wantFile(t, paths.executable, "updated binary")
	if runtime.GOOS == "linux" {
		info, _ := os.Stat(paths.executable)
		if info.Mode().Perm() != 0755 {
			t.Fatalf("executable permissions: %v", info.Mode())
		}
	}
}

func TestOptionalSettingsAreCopiedOnlyWhenAbsent(t *testing.T) {
	source, paths := fixture(t)
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.age", "config.master.age", "agent.connection.age", "agent.connection.json"} {
		from, to := filepath.Join(filepath.Dir(source), name), filepath.Join(paths.directory, name)
		put(t, from, "uploaded settings")
		if err := copyOptional(from, to); err != nil {
			t.Fatal(err)
		}
		wantFile(t, to, "uploaded settings")
		put(t, to, "installed settings")
		if err := copyOptional(from, to); err != nil {
			t.Fatal(err)
		}
		wantFile(t, to, "installed settings")
	}
	if err := copyOptional(filepath.Join(filepath.Dir(source), "absent"), filepath.Join(paths.directory, "absent")); err != nil {
		t.Fatal(err)
	}
}

func TestScriptReplacementPreservesEveryExistingVersion(t *testing.T) {
	_, paths := fixture(t)
	put(t, paths.script, "existing hook one\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.script, hook)
	wantFile(t, paths.script+".anquan.bak", "existing hook one\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.script + ".anquan.bak.1"); !os.IsNotExist(err) {
		t.Fatal("unchanged hook was backed up again")
	}
	put(t, paths.script, "existing hook two\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.script+".anquan.bak", "existing hook one\n")
	wantFile(t, paths.script+".anquan.bak.1", "existing hook two\n")
	wantFile(t, paths.script, hook)
}

func TestInstallFromArbitraryDirectoryAndRepeat(t *testing.T) {
	requireSymlinks(t)
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	put(t, filepath.Join(filepath.Dir(source), "config.age"), "encrypted configuration")
	moved, err := ensure(source, paths)
	if err != nil || !moved {
		t.Fatalf("install: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "encrypted configuration")
	wantFile(t, paths.script, hook)
	for _, name := range []string{"state", "logs", "textfile"} {
		info, err := os.Stat(filepath.Join(paths.directory, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("missing runtime directory %s: %v", name, err)
		}
	}
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH link: %q %v", target, err)
	}
	if moved, err := ensure(paths.executable, paths); err != nil || moved {
		t.Fatalf("repeat: moved=%t err=%v", moved, err)
	}
	if _, err := os.Stat(paths.sshrc + ".anquan.bak"); !os.IsNotExist(err) {
		t.Fatal("matching SSH link was backed up")
	}
}

func TestExistingSSHRCIsPreservedBeforeLinking(t *testing.T) {
	requireSymlinks(t)
	_, paths := fixture(t)
	put(t, paths.sshrc, "existing SSH initialization\n")
	if err := ensureSSHRC(paths.sshrc, paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.sshrc+".anquan.bak", "existing SSH initialization\n")
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH link: %q %v", target, err)
	}
}

func TestRefuseSSHDirectoriesAndSymlinkedInstallationDirectory(t *testing.T) {
	_, paths := fixture(t)
	if err := os.MkdirAll(paths.script, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ensureScript(paths.script); err == nil {
		t.Fatal("directory replaced by hook")
	}
	info, err := os.Stat(paths.script)
	if err != nil || !info.IsDir() {
		t.Fatal("existing directory changed")
	}
	requireSymlinks(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "install")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(link); err == nil {
		t.Fatal("symlink accepted as installation directory")
	}
}
