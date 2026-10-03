package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func filesTestConfig(t *testing.T, monitoring FilesMonitoringConfig) Config {
	t.Helper()
	base := t.TempDir()
	c := Config{OutputDir: filepath.Join(base, "output"), StateFile: filepath.Join(base, "state", "agent.json"), FilesMonitoring: &monitoring}
	if err := normalizeFilesMonitoring(c.FilesMonitoring, base, nativePathRules()); err != nil {
		t.Fatal(err)
	}
	return c
}

func filesCollectOK(t *testing.T, c Config) (FilesResult, *filesBaseline) {
	t.Helper()
	r, next, issues := collectFilesMonitoring(c, time.Now())
	if !r.Success || len(issues) > 0 || next == nil {
		t.Fatalf("collection failed: result=%+v issues=%+v", r, issues)
	}
	return r, next
}

func filesCommit(t *testing.T, c Config, next *filesBaseline) {
	t.Helper()
	if err := writeJSON(c.StateFile+".files", next, 0600); err != nil {
		t.Fatal(err)
	}
}

func filesAlertCount(r FilesResult, kind string) int {
	n := 0
	for _, alert := range r.Alerts {
		if alert.Kind == kind {
			n++
		}
	}
	return n
}

func TestFilesMonitoringRollingRecursiveLifecycle(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Dir: []string{"watched"}})
	root := c.FilesMonitoring.rules[0].Paths[0]
	put(t, filepath.Join(root, "nested", "changed"), "first")
	put(t, filepath.Join(root, "removed"), "remove")
	r, next := filesCollectOK(t, c)
	if !r.BaselineCreated || r.Scanned != 2 || len(r.Changes) != 0 || len(r.Alerts) != 0 {
		t.Fatalf("bad initial result: %+v", r)
	}
	for _, item := range r.Items {
		if item.Status != "baseline_created" || !validFileMD5(item.MD5) {
			t.Fatalf("missing initial hash/status: %+v", item)
		}
	}
	filesCommit(t, c, next)
	put(t, filepath.Join(root, "nested", "changed"), "second")
	put(t, filepath.Join(root, "added"), "new")
	if err := os.Remove(filepath.Join(root, "removed")); err != nil {
		t.Fatal(err)
	}
	r, next = filesCollectOK(t, c)
	if len(r.Changes) != 3 || filesAlertCount(r, "added") != 1 || filesAlertCount(r, "modified") != 1 || filesAlertCount(r, "deleted") != 1 {
		t.Fatalf("missing change notifications: %+v", r)
	}
	filesCommit(t, c, next)
	r, _ = filesCollectOK(t, c)
	if len(r.Changes) != 0 || len(r.Alerts) != 0 || r.BaselineCreated {
		t.Fatalf("rolling baseline did not advance: %+v", r)
	}
}

func TestFilesMonitoringAllowlistManyToManyAndPersistentMismatch(t *testing.T) {
	const abc = "900150983cd24fb0d6963f7d28e17f72"
	const def = "4ed9407630eb1000c0f6b63842defa7d"
	const empty = "d41d8cd98f00b204e9800998ecf8427e"
	c := filesTestConfig(t, FilesMonitoringConfig{Fils: []string{"a|b," + def + "," + abc + "," + empty}})
	root := filepath.Dir(c.OutputDir)
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	put(t, a, "abc")
	put(t, b, "def")
	r, next := filesCollectOK(t, c)
	if r.Scanned != 2 || len(r.Alerts) != 0 || r.Rules[0].Matched != 2 || r.Rules[0].Mismatched != 0 {
		t.Fatalf("allowlist incorrectly treated as positional: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, b, "unexpected")
	for i := 0; i < 2; i++ {
		r, next = filesCollectOK(t, c)
		if filesAlertCount(r, "md5_mismatch") != 1 || r.Rules[0].Matched != 1 || r.Rules[0].Mismatched != 1 {
			t.Fatalf("partial mismatch was lost on scan %d: %+v", i, r)
		}
		if len(r.Changes) != 0 {
			t.Fatalf("fixed allowlist treated as rolling content baseline: %+v", r.Changes)
		}
		filesCommit(t, c, next)
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	r, next = filesCollectOK(t, c)
	if filesAlertCount(r, "missing") != 1 || filesAlertCount(r, "deleted") != 1 || r.Rules[0].MissingRoots != 1 {
		t.Fatalf("fixed path deletion not detected: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, b, "def")
	r, _ = filesCollectOK(t, c)
	if filesAlertCount(r, "added") != 1 || r.Rules[0].Matched != 2 {
		t.Fatalf("fixed path restoration not detected: %+v", r)
	}
}

func TestFilesMonitoringSearchAndNoMatches(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Search: []string{"authorized_keys,home|root"}})
	base := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(base, "home", "user", ".ssh", "authorized_keys"), "alice")
	put(t, filepath.Join(base, "root", ".ssh", "authorized_keys"), "root")
	put(t, filepath.Join(base, "root", "authorized_keys.bak"), "ignored")
	r, next := filesCollectOK(t, c)
	if r.Scanned != 2 || len(r.Alerts) != 0 {
		t.Fatalf("search must recurse and match exact basename: %+v", r)
	}
	filesCommit(t, c, next)
	if err := os.Remove(filepath.Join(base, "home", "user", ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(base, "root", ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	r, next = filesCollectOK(t, c)
	if filesAlertCount(r, "deleted") != 2 || filesAlertCount(r, "not_found") != 1 {
		t.Fatalf("search deletion/missing notification absent: %+v", r)
	}
	filesCommit(t, c, next)
	r, _ = filesCollectOK(t, c)
	if filesAlertCount(r, "not_found") != 1 || len(r.Changes) != 0 {
		t.Fatalf("search absence must remain visible: %+v", r)
	}
	other := filesTestConfig(t, FilesMonitoringConfig{Search: []string{"id_rsa,empty"}})
	if err := os.Mkdir(other.FilesMonitoring.rules[0].Paths[0], 0700); err != nil {
		t.Fatal(err)
	}
	r, _ = filesCollectOK(t, other)
	if r.Scanned != 0 || filesAlertCount(r, "not_found") != 1 {
		t.Fatalf("initial missing search target silently skipped: %+v", r)
	}
}

func TestFilesMonitoringSearchAllowlistAndOverlappingRoots(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Search: []string{"authorized_keys,home|home/user,900150983cd24fb0d6963f7d28e17f72"}})
	base := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(base, "home", "user", "authorized_keys"), "abc")
	put(t, filepath.Join(base, "home", "other", "authorized_keys"), "wrong")
	r, _ := filesCollectOK(t, c)
	if r.Scanned != 2 || len(r.Items) != 2 || r.Rules[0].Matched != 1 || r.Rules[0].Mismatched != 1 || filesAlertCount(r, "md5_mismatch") != 1 {
		t.Fatalf("overlapping search duplicated results or bypassed allowlist: %+v", r)
	}
}

func TestFilesMonitoringOverlappingRulesHaveUniqueItemIdentity(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Dir: []string{"watched", "watched/child"}})
	base := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(base, "watched", "child", "file"), "before")
	r, next := filesCollectOK(t, c)
	if r.Scanned != 1 || len(r.Items) != 2 || r.Items[0].Rule == r.Items[1].Rule || r.Rules[0].Rule == r.Rules[1].Rule {
		t.Fatalf("overlapping rules have duplicate identities: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, filepath.Join(base, "watched", "child", "file"), "after")
	r, _ = filesCollectOK(t, c)
	if len(r.Changes) != 1 || filesAlertCount(r, "modified") != 1 {
		t.Fatalf("overlapping rules duplicated global change: %+v", r)
	}
}

func TestFilesMonitoringOverlappingAutoAndFixedPolicies(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Dir: []string{"watched"}, Fils: []string{"watched/file,900150983cd24fb0d6963f7d28e17f72"}})
	p := filepath.Join(filepath.Dir(c.OutputDir), "watched", "file")
	put(t, p, "abc")
	r, next := filesCollectOK(t, c)
	if r.Scanned != 1 || len(r.Alerts) != 0 || len(r.Items) != 2 {
		t.Fatalf("overlap failed initial checks: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, p, "changed")
	r, next = filesCollectOK(t, c)
	if filesAlertCount(r, "modified") != 1 || filesAlertCount(r, "md5_mismatch") != 1 {
		t.Fatalf("both explicit policies must be enforced: %+v", r)
	}
	filesCommit(t, c, next)
	r, _ = filesCollectOK(t, c)
	if len(r.Changes) != 0 || filesAlertCount(r, "md5_mismatch") != 1 {
		t.Fatalf("allowlist must stay fixed when overlapping auto baseline rolls: %+v", r)
	}
}

func TestFilesMonitoringMissingFixedPathDoesNotBlockAutoInitialization(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Fils: []string{"watched", "missing,900150983cd24fb0d6963f7d28e17f72"}})
	p := filepath.Join(filepath.Dir(c.OutputDir), "watched")
	put(t, p, "before")
	r, next := filesCollectOK(t, c)
	if !r.BaselineCreated || r.Scanned != 1 || filesAlertCount(r, "missing") != 1 {
		t.Fatalf("missing fixed path prevented independent auto baseline: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, p, "after")
	r, _ = filesCollectOK(t, c)
	if filesAlertCount(r, "missing") != 1 || filesAlertCount(r, "modified") != 1 {
		t.Fatalf("missing fixed path swallowed an auto file change: %+v", r)
	}
}

func TestFilesMonitoringMissingRootInitialAndAfterBaseline(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Fils: []string{"watched", "existing"}})
	base := filepath.Dir(c.OutputDir)
	root := filepath.Join(base, "watched")
	put(t, filepath.Join(base, "existing"), "stable")
	r, next := filesCollectOK(t, c)
	if !r.BaselineCreated || r.Scanned != 1 || filesAlertCount(r, "missing") != 1 {
		t.Fatalf("known initial absence blocked available files or lost alert: %+v", r)
	}
	filesCommit(t, c, next)
	put(t, filepath.Join(root, "file"), "before")
	r, next = filesCollectOK(t, c)
	if filesAlertCount(r, "added") != 1 || filesAlertCount(r, "missing") != 0 || r.Scanned != 2 {
		t.Fatalf("initially missing root appearance was not reported as added: %+v", r)
	}
	filesCommit(t, c, next)
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	r, next = filesCollectOK(t, c)
	if filesAlertCount(r, "missing") != 1 || filesAlertCount(r, "deleted") != 1 {
		t.Fatalf("missing established root must report deletion: %+v", r)
	}
	filesCommit(t, c, next)
	r, _ = filesCollectOK(t, c)
	if filesAlertCount(r, "missing") != 1 || len(r.Changes) != 0 {
		t.Fatalf("persistent missing root lost or repeated deletion: %+v", r)
	}
}

func TestFilesMonitoringDisabled(t *testing.T) {
	if err := normalizeFilesMonitoring(nil, "/base", targetPathRules(false)); err != nil {
		t.Fatal(err)
	}
	r, next, issues := collectFilesMonitoring(Config{}, time.Now())
	if r.Enabled || !r.Success || next != nil || len(issues) != 0 || len(r.Items) != 0 || len(r.Alerts) != 0 {
		t.Fatalf("disabled file monitoring produced work: %+v %+v", r, issues)
	}
}

func TestFilesMonitoringIncompleteScanPreservesBaseline(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Dir: []string{"good", "bad"}})
	base := filepath.Dir(c.OutputDir)
	good, bad := filepath.Join(base, "good"), filepath.Join(base, "bad")
	put(t, filepath.Join(good, "changed"), "before")
	put(t, filepath.Join(bad, "saved"), "stable")
	_, next := filesCollectOK(t, c)
	filesCommit(t, c, next)
	before := read(t, c.StateFile+".files")
	put(t, filepath.Join(good, "changed"), "after")
	if err := os.Rename(bad, bad+".aside"); err != nil {
		t.Fatal(err)
	}
	put(t, bad, "no longer a directory")
	r, next, issues := collectFilesMonitoring(c, time.Now())
	if r.Success || next != nil || len(issues) == 0 || len(r.Changes) != 0 || filesAlertCount(r, "inspection_error") == 0 {
		t.Fatalf("incomplete scan consumed baseline or invented deletions: %+v %+v", r, issues)
	}
	if read(t, c.StateFile+".files") != before {
		t.Fatal("collector changed saved baseline")
	}
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bad+".aside", bad); err != nil {
		t.Fatal(err)
	}
	r, _ = filesCollectOK(t, c)
	if len(r.Changes) != 1 || r.Changes[0].Kind != "modified" {
		t.Fatalf("change was lost when incomplete scan recovered: %+v", r)
	}
}

func TestFilesMonitoringInvalidBaselinePreserved(t *testing.T) {
	for _, bad := range []string{"malformed", "wrong-hash", "scope-change", "path-outside-scope"} {
		t.Run(bad, func(t *testing.T) {
			c := filesTestConfig(t, FilesMonitoringConfig{Fils: []string{"watched"}})
			root := c.FilesMonitoring.rules[0].Paths[0]
			put(t, root, "before")
			_, next := filesCollectOK(t, c)
			switch bad {
			case "malformed":
				put(t, c.StateFile+".files", "{broken")
			case "wrong-hash":
				next.Files[root] = "bad-hash"
				filesCommit(t, c, next)
			case "path-outside-scope":
				next.Files[filepath.Join(filepath.Dir(root), "unmonitored")] = "900150983cd24fb0d6963f7d28e17f72"
				filesCommit(t, c, next)
			case "scope-change":
				filesCommit(t, c, next)
				c.FilesMonitoring.Fils = []string{"other"}
				if err := normalizeFilesMonitoring(c.FilesMonitoring, filepath.Dir(c.OutputDir), nativePathRules()); err != nil {
					t.Fatal(err)
				}
			}
			before := read(t, c.StateFile+".files")
			r, next, issues := collectFilesMonitoring(c, time.Now())
			if r.Success || next != nil || len(issues) == 0 || r.BaselineCreated || read(t, c.StateFile+".files") != before {
				t.Fatalf("invalid baseline reset: %+v %+v", r, issues)
			}
		})
	}
}

func TestFilesMonitoringExcludesOwnArtifacts(t *testing.T) {
	c := filesTestConfig(t, FilesMonitoringConfig{Dir: []string{"."}})
	base := filepath.Dir(c.OutputDir)
	c.Setup = &SetupConfig{Logs: filepath.Join(base, "logs", "时间anquan.log"), Prom: filepath.Join(base, "prom", "时间process_monitor.prom")}
	put(t, filepath.Join(base, "watched"), "data")
	put(t, filepath.Join(c.OutputDir, "report.json"), "report")
	put(t, c.StateFile, "legacy state")
	put(t, c.StateFile+".processes", "process state")
	put(t, datedOutput(c.Setup.Logs, time.Now(), true), "log")
	put(t, datedOutput(c.Setup.Prom, time.Now(), false), "metrics")
	r, next := filesCollectOK(t, c)
	if r.Scanned != 1 {
		t.Fatalf("self artifacts were included: %+v", r)
	}
	filesCommit(t, c, next)
	r, _ = filesCollectOK(t, c)
	if r.Scanned != 1 || len(r.Changes) != 0 {
		t.Fatalf("own baseline triggered a change: %+v", r)
	}
}

func TestFilesMonitoringValidationAndTargetPaths(t *testing.T) {
	invalid := []FilesMonitoringConfig{
		{}, {Fils: []string{""}}, {Fils: []string{"a|"}}, {Fils: []string{"a,"}},
		{Fils: []string{"a,md51"}}, {Fils: []string{"a,900150983cd24fb0d6963f7d28e17f7z"}},
		{Fils: []string{"a|a"}}, {Fils: []string{"a", "./a"}}, {Fils: []string{"a"}, Dir: []string{"a"}},
		{Fils: []string{"a,900150983cd24fb0d6963f7d28e17f72,900150983cd24fb0d6963f7d28e17f72"}},
		{Search: []string{"name"}}, {Search: []string{"../name,/root"}}, {Search: []string{"name|other,/root"}},
		{Search: []string{"name,/root|/root"}}, {Search: []string{"name,/root", "name,/root"}},
	}
	for i, c := range invalid {
		if err := normalizeFilesMonitoring(&c, "/base", targetPathRules(false)); err == nil {
			t.Errorf("invalid entry %d accepted: %+v", i, c)
		}
	}
	c := FilesMonitoringConfig{Fils: []string{"/etc/ssh/a|/etc/ssh/b,900150983CD24FB0D6963F7D28E17F72"}, Search: []string{"id_rsa,/root|/home"}}
	if err := normalizeFilesMonitoring(&c, "/base", targetPathRules(false)); err != nil {
		t.Fatal(err)
	}
	if c.rules[0].Paths[0] != "/etc/ssh/a" || c.rules[0].Hashes[0] != strings.ToLower("900150983CD24FB0D6963F7D28E17F72") {
		t.Fatalf("cross-host normalization changed Linux paths/hashes: %+v", c.rules)
	}
	c = FilesMonitoringConfig{Fils: []string{"C:/Etc/A|c:/etc/a"}}
	if err := normalizeFilesMonitoring(&c, "C:/base", targetPathRules(true)); err == nil {
		t.Fatal("Windows case-insensitive duplicate accepted")
	}
}
