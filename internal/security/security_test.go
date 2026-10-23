package security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls       []string
	values      map[string]string
	fail        func(string, []string) error
	missing     map[string]bool
	rootDir     string
	cadState    string
	burstAction string
}

func (r *fakeRunner) LookPath(n string) (string, error) {
	if r.missing[n] {
		return "", os.ErrNotExist
	}
	return "/usr/sbin/" + n, nil
}
func (r *fakeRunner) Run(ctx context.Context, n string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.calls = append(r.calls, n+" "+strings.Join(args, " "))
	if r.fail != nil {
		if e := r.fail(n, args); e != nil {
			return "", e
		}
	}
	if n == "auditctl" && len(args) > 0 && args[0] == "-s" {
		return "enabled 1\nlost 0\n", nil
	}
	if n == "sysctl" && len(args) > 1 {
		if args[0] == "-n" {
			return r.values[args[1]], nil
		}
		if args[0] == "-w" {
			p := strings.SplitN(args[1], "=", 2)
			r.values[p[0]] = p[1]
			return "", nil
		}
	}
	if n == "sshd" && len(args) > 0 && args[0] == "-T" {
		return "port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\nallowusers deploy\n", nil
	}
	if n == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "is-enabled":
			if len(args) > 1 && args[1] == "ctrl-alt-del.target" && r.cadState != "" {
				return r.cadState, nil
			}
			return "static", nil
		case "show":
			if len(args) > 1 && args[1] == "--property=CtrlAltDelBurstAction" {
				if r.burstAction == "" {
					return "reboot-force", nil
				}
				return r.burstAction, nil
			}
		case "mask":
			r.cadState = "masked"
			if len(args) > 1 && args[1] == "--runtime" {
				r.cadState = "masked-runtime"
			}
		case "unmask":
			r.cadState = "static"
		case "daemon-reexec":
			data, _ := os.ReadFile(filepath.Join(r.rootDir, filepath.FromSlash(strings.TrimPrefix(ctrlAltDelConfigPath, "/"))))
			r.burstAction = "reboot-force"
			if strings.Contains(string(data), "CtrlAltDelBurstAction=none") {
				r.burstAction = "none"
			}
		}
	}
	return "", nil
}
func testManager(t *testing.T, c Config) (*Manager, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	runner := &fakeRunner{values: map[string]string{}, missing: map[string]bool{}, rootDir: root}
	m := NewManager(c, filepath.Join(root, "state"))
	m.RootDir = root
	m.Runner = runner
	return m, runner
}
func put(t *testing.T, m *Manager, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(m.path(path)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.path(path), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestConfigRejectsUnsafeInput(t *testing.T) {
	cases := []Config{
		{Auditd: AuditdConfig{Rules: []string{"-D"}}}, {Auditd: AuditdConfig{Rules: []string{"-a always,exit -k anquan_exec -e 0"}}},
		{Policies: PolicyConfig{Sysctl: map[string]string{"kernel.kptr_restrict": "1\nnet.ipv4.ip_forward=1"}}},
		{Tetragon: TetragonConfig{DownloadURL: "http://example.com/a.tar.gz"}}, {Tetragon: TetragonConfig{DownloadURL: "https://example.com/a.tar.gz"}},
		{Tetragon: TetragonConfig{Config: "server-address: 0.0.0.0:1234"}},
		{Sudo: SudoConfig{Grants: []SudoGrant{{User: "deploy", Commands: []string{"/usr/bin/systemctl *"}}}}},
		{Policies: PolicyConfig{SSH: SSHConfig{AllowUsers: []string{"root\nPermitRootLogin yes"}}}},
		{Policies: PolicyConfig{Mode: "enforce", GRUB: GRUBConfig{Enabled: true, PasswordHash: "$6$wrong"}}},
	}
	for i, c := range cases {
		c.Normalize()
		if c.Validate() == nil {
			t.Errorf("case %d accepted unsafe configuration", i)
		}
	}
}
func TestApplySudoAndDisablePreserveOtherFiles(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true, IOLogging: true}})
	put(t, m, "/etc/sudoers.d/admin", []byte("root ALL=(ALL) ALL\n"))
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.path(sudoConfigPath))
	if err != nil || !bytes.Contains(raw, []byte("log_input,log_output")) {
		t.Fatalf("sudo configuration missing: %q %v", raw, err)
	}
	m2 := NewManager(m.Config, m.OutputDir)
	m2.RootDir = m.RootDir
	m2.Runner = m.Runner
	for _, s := range m2.Status(context.Background()) {
		if s.AppliedAt == nil {
			t.Error("last application time did not survive Manager recreation")
		}
	}
	m.Config.Enabled = false
	if _, err = m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(m.path(sudoConfigPath)); !os.IsNotExist(err) {
		t.Fatal("managed sudo file was not removed")
	}
	if _, err = os.Stat(m.path("/etc/sudoers.d/admin")); err != nil {
		t.Fatal("administrator sudo configuration removed")
	}
}
func TestApplyRejectsUnownedFile(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true}})
	put(t, m, sudoConfigPath, []byte("# administrator configuration"))
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("unowned configuration overwritten")
	}
}
func TestValidationFailureRestoresPreviousConfiguration(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true}})
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.path(sudoConfigPath))
	r.fail = func(n string, args []string) error {
		if n == "visudo" {
			return errors.New("invalid requested sudoers")
		}
		return nil
	}
	m.Config.Sudo.IOLogging = true
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("invalid config accepted")
	}
	after, _ := os.ReadFile(m.path(sudoConfigPath))
	if !bytes.Equal(before, after) {
		t.Fatal("old config was not restored")
	}
	old, err := m.loadManifest()
	if err != nil || old.Files[sudoConfigPath] != hashString(string(before)) {
		t.Fatal("failed config committed to manifest")
	}
}
func TestSysctlOriginalValuesRestoredOnDisable(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}}})
	r.values["kernel.kptr_restrict"] = "0"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.values["kernel.kptr_restrict"] != "2" {
		t.Fatal("sysctl not applied")
	}
	m.Config.Policies.Sysctl["kernel.kptr_restrict"] = "1"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.values["kernel.kptr_restrict"] != "0" {
		t.Fatalf("original runtime value lost: %q", r.values["kernel.kptr_restrict"])
	}
}
func TestAuditCleanupPreservesAdministratorFiles(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true, AuditExec: true}})
	put(t, m, "/etc/audit/rules.d/admin.rules", []byte("-w /etc/passwd -p wa -k admin\n"))
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "auditctl -D") {
			t.Fatal("audit rules were cleared in bulk")
		}
	}
	state, err := m.loadManifest()
	if err != nil || len(state.AuditRules) != 0 {
		t.Fatalf("disabled agent retained runtime rule ownership: %#v %v", state.AuditRules, err)
	}
	if _, err := os.Stat(m.path("/etc/audit/rules.d/admin.rules")); err != nil {
		t.Fatal(err)
	}
}
func TestAuditModeDoesNotWritePoliciesOrGrants(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true, Grants: []SudoGrant{{User: "deploy", Commands: []string{"/usr/bin/id"}}}}, Policies: PolicyConfig{Mode: "audit", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}, SessionTimeoutSeconds: 900}})
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sysctlConfigPath, sessionConfigPath} {
		if _, err := os.Stat(m.path(p)); !os.IsNotExist(err) {
			t.Fatal("audit mode wrote a host policy")
		}
	}
	raw, _ := os.ReadFile(m.path(sudoConfigPath))
	if bytes.Contains(raw, []byte("deploy ALL=")) {
		t.Fatal("audit mode applied sudo grants")
	}
}
func TestAuditRecordsAreCorrelatedAndReplayStableIDs(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}})
	put(t, m, "/var/log/audit/audit.log", []byte("type=SYSCALL msg=audit(1700000000.001:42): auid=1000 uid=0 pid=7 success=yes key=\"anquan_exec\"\ntype=EXECVE msg=audit(1700000000.001:42): argc=2 a0=\"id\" a1=\"-u\"\ntype=EOE msg=audit(1700000000.001:42):\n"))
	var id string
	if err := m.Poll(context.Background(), func(e Event) error { id = e.ID; return errors.New("queue full") }); err == nil {
		t.Fatal("queue error ignored")
	}
	events := []Event{}
	if err := m.Poll(context.Background(), func(e Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != id || events[0].Data["kind"] != "exec" {
		t.Fatalf("event replay not stable: %+v", events)
	}
	fields := events[0].Data["fields"].(map[string]string)
	if fields["auid"] != "1000" || fields["a0"] != "id" {
		t.Fatalf("missing correlated identity/command: %+v", fields)
	}
	if err := m.Poll(context.Background(), func(e Event) error { t.Error("event emitted twice after checkpoint"); return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(m.statePath())
	if bytes.Contains(raw, []byte("audit_id")) {
		t.Fatal("collector checkpoint is plaintext")
	}
}
func TestLogTruncationReportsGapAndContinuesOnce(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	path := "/var/log/tetragon/tetragon.log"
	put(t, m, path, []byte("{\"process_exec\":{\"process\":{\"pid\":12345}}}\n"))
	var events []Event
	emit := func(e Event) error { events = append(events, e); return nil }
	if err := m.Poll(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	put(t, m, path, []byte("{\"process_exit\":{}}\n"))
	if err := m.Poll(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	count := len(events)
	if count != 3 {
		t.Fatalf("expected exec, gap, exit; got %+v", events)
	}
	if err := m.Poll(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != count {
		t.Fatal("truncation repeatedly reported")
	}
}
func TestSudoUploadSameSessionGenerationAndBinaryData(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true, IOLogging: true, UploadIO: true}})
	files := map[string][]byte{"log": []byte("timestamp:user:root:root:pts/0:80:24\n/tmp\nid\n"), "timing": []byte("1 0.01 3\n"), "stdout": bytes.Repeat([]byte{0, 1, 2, 255}, 10000)}
	old := time.Now().Add(-time.Minute)
	for name, b := range files {
		p := "/var/log/anquan-sudo-io/00/00/AB/" + name
		put(t, m, p, b)
		if err := os.Chtimes(m.path(p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	events := []Event{}
	if err := m.Poll(context.Background(), func(e Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	generation := ""
	received := map[string][]byte{}
	complete := map[string]bool{}
	for _, e := range events {
		if e.Data["kind"] != "io_chunk" {
			continue
		}
		d := e.Data["details"].(map[string]any)
		g := d["generation"].(string)
		if generation != "" && generation != g {
			t.Fatal("files split into separate session generations")
		}
		generation = g
		name := d["file"].(string)
		b, err := base64.StdEncoding.DecodeString(d["content_base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		received[name] = append(received[name], b...)
		complete[name] = d["complete"].(bool)
	}
	for name, b := range files {
		if !bytes.Equal(received[name], b) || !complete[name] {
			t.Fatalf("incomplete file %s", name)
		}
	}
	before := len(events)
	if err := m.Poll(context.Background(), func(e Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != before {
		t.Fatal("completed I/O files uploaded again")
	}
}
func TestArchiveRejectsTraversalAndLinks(t *testing.T) {
	for _, entry := range []tar.Header{{Name: "../escape", Mode: 0755, Typeflag: tar.TypeReg}, {Name: "package/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}} {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&entry); err != nil {
			t.Fatal(err)
		}
		tw.Close()
		gz.Close()
		if err := extractPackage(b.Bytes(), t.TempDir()); err == nil {
			t.Fatalf("unsafe archive accepted: %+v", entry)
		}
	}
}
func TestFirewallUsesActualSSHPortAndOwnTable(t *testing.T) {
	m, runner := testManager(t, Config{})
	sshHost(t, m, runner)
	raw, err := m.firewallRules(context.Background(), []string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "tcp dport { 2222 }") || strings.Contains(raw, "flush ruleset") {
		t.Fatal(raw)
	}
	if !strings.Contains(raw, "table inet anquan_ssh") || !strings.Contains(raw, "ip6 saddr") {
		t.Fatal(raw)
	}
}
func TestRecoveryRestoresInterruptedFile(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: false})
	p := sudoConfigPath
	put(t, m, p, []byte("new"))
	previous := manifest{Files: map[string]string{p: hashString("old")}}
	next := manifest{Files: map[string]string{p: hashString("new")}}
	journal := transactionJournal{Before: []snapshot{{Path: p, Exists: true, Data: []byte("old"), Mode: 0440}}, Previous: previous, Next: next}
	if err := writePrivateJSON(m.journalPath(), "security-transaction", journal); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(m.manifestPath(), "security-managed", previous); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.path(p)); !os.IsNotExist(err) {
		t.Fatal("disabled configuration was not removed after recovery")
	}
}
func TestCancelledStatusUsesCallerContext(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.fail = func(n string, args []string) error { return fmt.Errorf("unexpected active call %s", n) }
	started := time.Now()
	_ = m.Status(ctx)
	if time.Since(started) > time.Second {
		t.Fatal("status ignored cancellation")
	}
}
