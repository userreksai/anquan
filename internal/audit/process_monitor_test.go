package audit

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func processTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{StateFile: filepath.Join(t.TempDir(), "state.json"), ProcessMonitoring: &ProcessMonitoringConfig{Process: &ProcessListConfig{}}}
}

func processFixtureScanner(commands map[string]int) func() (map[string]int, error) {
	return func() (map[string]int, error) { return commands, nil }
}

func TestProcessMonitoringInitialAndRollingCounts(t *testing.T) {
	c := processTestConfig(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r, next, issues := collectProcessMonitoringWithScanner(c, now, processFixtureScanner(map[string]int{"/usr/sbin/sshd -D": 1, "/usr/bin/worker": 2}))
	if len(issues) != 0 || !r.Success || !r.BaselineCreated || next == nil || r.Scanned != 3 || len(r.Changes) != 0 || len(r.Alerts) != 0 {
		t.Fatalf("initial snapshot: result=%+v next=%+v issues=%+v", r, next, issues)
	}
	if _, err := os.Stat(c.StateFile + ".processes"); !os.IsNotExist(err) {
		t.Fatalf("collector wrote state before report publication: %v", err)
	}
	if err := writeJSON(c.StateFile+".processes", next, 0600); err != nil {
		t.Fatal(err)
	}
	updated := map[string]int{"/usr/bin/worker": 1, "/usr/bin/new": 2}
	r, next, issues = collectProcessMonitoringWithScanner(c, now.Add(time.Minute), processFixtureScanner(updated))
	want := []ProcessChange{
		{Command: "/usr/bin/new", Kind: "added", Before: 0, After: 2},
		{Command: "/usr/bin/worker", Kind: "deleted", Before: 2, After: 1},
		{Command: "/usr/sbin/sshd -D", Kind: "deleted", Before: 1, After: 0},
	}
	if len(issues) != 0 || !r.Success || r.BaselineCreated || !reflect.DeepEqual(r.Changes, want) || len(r.Alerts) != 3 || next == nil {
		t.Fatalf("changed snapshot: result=%+v next=%+v issues=%+v", r, next, issues)
	}
	if err := writeJSON(c.StateFile+".processes", next, 0600); err != nil {
		t.Fatal(err)
	}
	r, next, issues = collectProcessMonitoringWithScanner(c, now.Add(2*time.Minute), processFixtureScanner(updated))
	if len(issues) != 0 || len(r.Changes) != 0 || len(r.Alerts) != 0 || next == nil {
		t.Fatalf("rolling baseline must not repeat changes: %+v %+v", r, issues)
	}
	r, _, issues = collectProcessMonitoringWithScanner(c, now.Add(3*time.Minute), processFixtureScanner(map[string]int{"/usr/bin/worker": 3, "/usr/bin/new": 2}))
	if len(issues) != 0 || len(r.Changes) != 1 || r.Changes[0].Kind != "added" || r.Changes[0].Before != 1 || r.Changes[0].After != 3 {
		t.Fatalf("additional duplicate instances were not detected: %+v %+v", r, issues)
	}
}

func TestProcessMonitoringAlternativesAndExactCommand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		missing int
	}{
		{name: "first alternative", command: "/usr/sbin/sshd -D"},
		{name: "other system alternative", command: "/usr/sbin/ssh -D"},
		{name: "substring not accepted", command: "/usr/sbin/sshd -D-extra", missing: 1},
		{name: "wrapper not accepted", command: "sh -c /usr/sbin/sshd -D", missing: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := processTestConfig(t)
			c.ProcessMonitoring = &ProcessMonitoringConfig{Exists: []string{`"/usr/sbin/sshd   -D"|"/usr/sbin/ssh -D"|'/sbin/sshd -D'`}}
			if err := normalizeProcessMonitoring(c.ProcessMonitoring); err != nil {
				t.Fatal(err)
			}
			r, next, issues := collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{tc.command: 1}))
			if len(issues) != 0 || !r.Success || r.Missing != tc.missing || len(r.Alerts) != tc.missing || next != nil || len(r.Items) != 1 || r.Items[0].Exists != (tc.missing == 0) {
				t.Fatalf("unexpected exists result: %+v issues=%+v", r, issues)
			}
		})
	}
}

func TestProcessWhitelistSuppressesChangesButNotExists(t *testing.T) {
	c := processTestConfig(t)
	c.ProcessMonitoring.Exists = []string{"/usr/sbin/sshd -D"}
	c.ProcessMonitoring.Process.Whitelist = []string{"/usr/sbin/sshd -D"}
	now := time.Now()
	r, next, issues := collectProcessMonitoringWithScanner(c, now, processFixtureScanner(map[string]int{"/usr/sbin/sshd -D": 1, "/usr/bin/worker": 1}))
	if len(issues) != 0 || next == nil || r.Missing != 0 || len(r.Inventory) != 2 || !r.Inventory[1].Whitelisted || len(next.Processes) != 1 {
		t.Fatalf("initial whitelist result: %+v %+v %+v", r, next, issues)
	}
	if err := writeJSON(c.StateFile+".processes", next, 0600); err != nil {
		t.Fatal(err)
	}
	r, _, issues = collectProcessMonitoringWithScanner(c, now.Add(time.Minute), processFixtureScanner(map[string]int{"/usr/bin/worker": 1}))
	if len(issues) != 0 || r.Missing != 1 || len(r.Changes) != 0 || len(r.Alerts) != 1 || r.Alerts[0].Kind != "missing" {
		t.Fatalf("required whitelisted process must still alert: %+v %+v", r, issues)
	}
	r, _, issues = collectProcessMonitoringWithScanner(c, now.Add(2*time.Minute), processFixtureScanner(map[string]int{"/usr/bin/worker": 1, "/usr/sbin/sshd -D": 7}))
	if len(issues) != 0 || r.Missing != 0 || len(r.Changes) != 0 || len(r.Alerts) != 0 {
		t.Fatalf("whitelisted instance count must not alert: %+v %+v", r, issues)
	}
}

func TestProcessScanFailurePreservesBaseline(t *testing.T) {
	c := processTestConfig(t)
	c.ProcessMonitoring.Exists = []string{"/usr/sbin/sshd -D"}
	_, baseline, _ := collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{"/usr/sbin/sshd -D": 1}))
	if err := writeJSON(c.StateFile+".processes", baseline, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(c.StateFile + ".processes")
	if err != nil {
		t.Fatal(err)
	}
	r, next, issues := collectProcessMonitoringWithScanner(c, time.Now(), func() (map[string]int, error) {
		return map[string]int{"/usr/bin/partial": 1}, os.ErrPermission
	})
	if r.Success || next != nil || len(issues) != 1 || len(r.Changes) != 0 || len(r.Alerts) != 0 || len(r.Items) != 0 {
		t.Fatalf("failed scan should be explicit without false alarms: %+v next=%+v issues=%+v", r, next, issues)
	}
	after, err := os.ReadFile(c.StateFile + ".processes")
	if err != nil || string(before) != string(after) {
		t.Fatalf("failed scan changed baseline: %v", err)
	}
}

func TestProcessInvalidBaselineDoesNotReset(t *testing.T) {
	for _, invalid := range []string{"{", `{"version":1,"scope":"wrong","processes":{}}`} {
		t.Run(invalid, func(t *testing.T) {
			c := processTestConfig(t)
			if err := os.WriteFile(c.StateFile+".processes", []byte(invalid), 0600); err != nil {
				t.Fatal(err)
			}
			r, next, issues := collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{"/usr/bin/worker": 1}))
			if r.Success || r.BaselineCreated || next != nil || len(issues) != 1 || len(r.Changes) != 0 {
				t.Fatalf("invalid state silently reset: %+v %+v %+v", r, next, issues)
			}
		})
	}
}

func TestNormalizeProcessMonitoring(t *testing.T) {
	c := &ProcessMonitoringConfig{Exists: []string{`"/usr/sbin/sshd  -D" | '/usr/sbin/ssh -D'`}, Process: &ProcessListConfig{Whitelist: []string{"/usr/bin/a|/usr/bin/b", " /usr/bin/a "}}}
	if err := normalizeProcessMonitoring(c); err != nil {
		t.Fatal(err)
	}
	if c.Exists[0] != "/usr/sbin/ssh -D|/usr/sbin/sshd -D" || !reflect.DeepEqual(c.Process.Whitelist, []string{"/usr/bin/a", "/usr/bin/b"}) {
		t.Fatalf("unexpected normalization: %+v %+v", c, c.Process)
	}
	for _, invalid := range []string{"", "a|", "|a", `"a`, "a\x00b", "a\nb"} {
		if err := normalizeProcessMonitoring(&ProcessMonitoringConfig{Exists: []string{invalid}}); err == nil {
			t.Errorf("accepted invalid rule %q", invalid)
		}
	}
	if err := normalizeProcessMonitoring(&ProcessMonitoringConfig{}); err == nil {
		t.Fatal("accepted empty process monitoring module")
	}
	if err := normalizeProcessMonitoring(&ProcessMonitoringConfig{Exists: []string{"a|b", "b|a"}}); err == nil {
		t.Fatal("accepted duplicate rules")
	}
}

func TestProcessDisabledDoesNotScan(t *testing.T) {
	r, next, issues := collectProcessMonitoringWithScanner(Config{}, time.Now(), func() (map[string]int, error) {
		t.Fatal("disabled collector called scanner")
		return nil, nil
	})
	if r.Enabled || !r.Success || next != nil || len(issues) != 0 {
		t.Fatalf("disabled result: %+v %+v %+v", r, next, issues)
	}
}

func TestProcScannerInventorySelfAndKernelThreads(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"100":  "/usr/sbin/sshd\x00-D\x00",
		"101":  "/usr/bin/worker\x00--serve\x00",
		"102":  "/usr/bin/worker\x00--serve\x00",
		"103":  "/usr/bin/anqu\x00daemon\x00",
		"104":  "",
		"self": "/usr/bin/ignored\x00",
	}
	for pid, cmd := range fixtures {
		if err := os.Mkdir(filepath.Join(root, pid), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cmdline"), []byte(cmd), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "104", "comm"), []byte("kworker/0:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	counts, err := scanProcProcesses(root, 103)
	want := map[string]int{"/usr/sbin/sshd -D": 1, "/usr/bin/worker --serve": 2, "[kworker/0:1]": 1}
	if err != nil || !reflect.DeepEqual(counts, want) {
		t.Fatalf("scan mismatch: %+v %v", counts, err)
	}
}

func TestProcScannerUnreadableFilesAreNotDeletions(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "100"), 0700); err != nil {
		t.Fatal(err)
	}
	// A missing cmdline in a still-existing PID directory is an incomplete
	// collection, not proof that the process exited.
	counts, err := scanProcProcesses(root, -1)
	if counts != nil || err == nil || !strings.Contains(err.Error(), "cmdline") {
		t.Fatalf("incomplete proc entry accepted: %+v %v", counts, err)
	}
	missingDir := filepath.Join(root, "already-exited")
	if !processDisappeared(missingDir, os.ErrNotExist) {
		t.Fatal("normal exited process was not recognized")
	}
	if processDisappeared(missingDir, os.ErrPermission) || processDisappeared(missingDir, errors.New("I/O error")) {
		t.Fatal("permission/I/O failure mistaken for a normal exit")
	}
}
