package audit

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"anqu/internal/sealed"
)

func TestSessionRebaselinesFilesAndPreservesLoginCursor(t *testing.T) {
	c := NewSession(monitoringTestConfig(t))
	base := filepath.Dir(c.OutputDir)
	put(t, c.Login.Path, loginJSON("old-login", "old", time.Now()))
	first, _ := runOK(t, c)
	if !first.Files.BaselineCreated || len(first.Login.Records) != 1 {
		t.Fatal("initial baseline/login missing")
	}
	// Change both content and monitoring scope while the agent is stopped.
	put(t, filepath.Join(base, "watched", "app.conf"), "changed while stopped")
	put(t, filepath.Join(base, "new-root", "app.conf"), "new scope")
	c.FilesMonitoring.Dir = append(c.FilesMonitoring.Dir, "new-root")
	if err := normalizeFilesMonitoring(c.FilesMonitoring, base, nativePathRules()); err != nil {
		t.Fatal(err)
	}
	c = NewSession(c)
	restarted, _ := runOK(t, c)
	if !restarted.Files.BaselineCreated || len(restarted.Files.Changes) != 0 || len(restarted.Login.Records) != 0 {
		t.Fatalf("restart did not rebaseline/deduplicate: %+v", restarted)
	}
	put(t, filepath.Join(base, "new-root", "app.conf"), "changed while running")
	put(t, c.Login.Path, read(t, c.Login.Path)+loginJSON("new-login", "new", time.Now()))
	next, _ := runOK(t, c)
	if next.Files.BaselineCreated || len(next.Files.Changes) != 1 || next.Files.Changes[0].Kind != "modified" || len(next.Login.Records) != 1 || next.Login.Records[0].User != "new-login" {
		t.Fatalf("later scan lost change/login: %+v", next)
	}
}

func TestSessionMigratesEveryLegacyStateIncludingDisabledModules(t *testing.T) {
	c := NewSession(monitoringTestConfig(t))
	c.FilesMonitoring = nil
	// Obtain a valid old login cursor, then write it in the pre-upgrade format.
	put(t, c.Login.Path, loginJSON("PRIVATE_LOGIN", "old", time.Now()))
	_, login, issues := collectSSHLogins(c, time.Now())
	if len(issues) != 0 || login == nil {
		t.Fatal(issues)
	}
	if err := writeJSON(c.StateFile+".logins", login, 0600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".files", ".processes"} {
		put(t, c.StateFile+suffix, `{"PRIVATE_PATH":"PRIVATE_HASH"}`)
	}
	r, _ := runOK(t, c)
	if len(r.Login.Records) != 0 {
		t.Fatal("migration replayed old logins")
	}
	for suffix, kind := range map[string]string{"": "md5", ".files": "files", ".processes": "processes", ".logins": "login"} {
		path := c.StateFile + suffix
		data := []byte(read(t, path))
		if !sealed.IsState(data) || bytes.Contains(data, []byte("PRIVATE_")) {
			t.Fatalf("plaintext state remains in %s", suffix)
		}
		if _, err := sealed.OpenState(data, kind); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
			t.Fatalf("wrong state permissions: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(c.StateFile))
	if err != nil || len(entries) != 5 { // Four encrypted states and one empty lock.
		t.Fatalf("unexpected plaintext backup/key/temp file: %v %v", entries, err)
	}
}

func TestSessionFailureRetriesBeforeActivatingBaseline(t *testing.T) {
	for _, failure := range []string{"collection", "publication", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c := NewSession(monitoringTestConfig(t))
			// Complete one lifetime, then start a fresh one with an existing baseline.
			runOK(t, c)
			c = NewSession(c)
			base := filepath.Dir(c.OutputDir)
			root := filepath.Join(base, "watched")
			state := c.StateFile + ".files"
			savedProm := c.Setup.Prom
			if err := prepareSession(c); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "collection":
				c.FilesMonitoring.rules[0].Paths = []string{filepath.Join(root, "app.conf")} // dir rule on a file
			case "publication":
				blocked := filepath.Join(base, "blocked")
				put(t, blocked, "not a directory")
				c.Setup.Prom = filepath.Join(blocked, "report.prom")
			case "commit":
				if err := os.Remove(state); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			}
			r, _, err := Run(c)
			if err == nil && r.Success {
				t.Fatal("expected failure")
			}
			if c.session.committed["files"] {
				t.Fatal("failed initial scan activated baseline")
			}
			c.FilesMonitoring.rules[0].Paths = []string{root}
			c.Setup.Prom = savedProm
			if failure == "commit" {
				if err := os.Remove(state); err != nil {
					t.Fatal(err)
				}
			}
			retry, _ := runOK(t, c)
			if !retry.Files.BaselineCreated || !c.session.committed["files"] {
				t.Fatal("initial baseline was not retried")
			}
			put(t, filepath.Join(root, "app.conf"), "after successful retry")
			later, _ := runOK(t, c)
			if later.Files.BaselineCreated || len(later.Files.Changes) != 1 {
				t.Fatal("later scan did not compare with committed baseline")
			}
		})
	}
}

func TestSessionRebaselinesUnknownMD5AndKeepsKnownValues(t *testing.T) {
	c := NewSession(monitoringTestConfig(t))
	c.FilesMonitoring.Dir = []string{"watched,900150983cd24fb0d6963f7d28e17f72"}
	if err := normalizeFilesMonitoring(c.FilesMonitoring, filepath.Dir(c.OutputDir), nativePathRules()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c = NewSession(c)
		r, _ := runOK(t, c)
		if !r.Files.BaselineCreated || len(r.Files.Alerts) != 0 || r.Files.Rules[0].BaselineTracked != 1 {
			t.Fatal("restart rejected initial unknown MD5")
		}
		path := filepath.Join(filepath.Dir(c.OutputDir), "watched", "app.conf")
		put(t, path, strings.Repeat("unknown", i+1))
		r, _ = runOK(t, c)
		if filesAlertCount(r.Files, "modified") != 1 {
			t.Fatal("unknown content change was lost")
		}
	}
	put(t, filepath.Join(filepath.Dir(c.OutputDir), "watched", "app.conf"), "abc")
	r, _ := runOK(t, c)
	if len(r.Files.Alerts) != 0 || r.Files.Rules[0].Matched != 1 {
		t.Fatal("known MD5 must be accepted after unknown content")
	}
}

func TestSessionRejectsTamperingAfterStartup(t *testing.T) {
	for _, plaintext := range []bool{false, true} {
		c := NewSession(monitoringTestConfig(t))
		runOK(t, c)
		path := c.StateFile + ".files"
		bad := []byte(read(t, path))
		if plaintext {
			var err error
			bad, err = sealed.OpenState(bad, "files")
			if err != nil {
				t.Fatal(err)
			}
		} else {
			bad[len(bad)-1] ^= 1
		}
		put(t, path, string(bad))
		r, _, err := Run(c)
		if err != nil || r.Files.Success || r.Files.BaselineCreated || read(t, path) != string(bad) {
			t.Fatal("tampered state was accepted or silently replaced")
		}
	}
}

func TestSessionRebaselinesLegacyMD5(t *testing.T) {
	c := NewSession(testConfig(t))
	runOK(t, c)
	c.MD5.Recursive = false
	put(t, filepath.Join(c.MD5.Paths[0], "app.conf"), "new lifetime")
	c = NewSession(c)
	r, _ := runOK(t, c)
	if !r.MD5.BaselineCreated || len(r.MD5.Changes) != 0 {
		t.Fatal("legacy MD5 did not rebaseline")
	}
	put(t, filepath.Join(c.MD5.Paths[0], "app.conf"), "running change")
	r, _ = runOK(t, c)
	if r.MD5.BaselineCreated || len(r.MD5.Changes) != 1 {
		t.Fatal("legacy MD5 lost subsequent change")
	}
}

func TestSessionRebaselinesProcessesAndKeepsRequiredProcesses(t *testing.T) {
	c := processTestConfig(t)
	_, old, _ := collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{"old": 1}))
	if err := writeState(c.StateFile+".processes", "processes", old); err != nil {
		t.Fatal(err)
	}
	c.ProcessMonitoring.Process.Whitelist = []string{"old"}
	c.ProcessMonitoring.Exists = []string{"required"}
	c = NewSession(c)
	r, next, issues := collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{"new": 1}))
	if len(issues) != 0 || !r.BaselineCreated || len(r.Changes) != 0 || r.Missing != 1 || next == nil {
		t.Fatalf("process rebaseline/exists failed: %+v %v", r, issues)
	}
	if err := writeState(c.StateFile+".processes", "processes", next); err != nil {
		t.Fatal(err)
	}
	c.session.committed["processes"] = true
	r, _, issues = collectProcessMonitoringWithScanner(c, time.Now(), processFixtureScanner(map[string]int{"new": 2}))
	if len(issues) != 0 || r.BaselineCreated || len(r.Changes) != 1 {
		t.Fatal("process changes after startup were lost")
	}
}

// Cancel only once a second real service scan reports a change. This exercises
// the production Serve entry point, rather than just manually creating sessions.
type serviceScanWriter struct {
	cancel context.CancelFunc
	path   string
	scans  int
	log    strings.Builder
}

func (w *serviceScanWriter) Write(p []byte) (int, error) {
	w.log.Write(p)
	if bytes.Contains(p, []byte(`"event":"scan_complete"`)) {
		w.scans++
		if w.scans == 1 {
			if err := os.WriteFile(w.path, []byte("changed during service"), 0600); err != nil {
				return 0, err
			}
		} else {
			w.cancel()
		}
	}
	return len(p), nil
}

var _ io.Writer = (*serviceScanWriter)(nil)

func TestServeStartsOnlyOneFreshBaselinePerLifetime(t *testing.T) {
	c := monitoringTestConfig(t)
	runOK(t, c)
	// An old invalid baseline must not prevent service startup.
	put(t, c.StateFile+".files", "{old incompatible state")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w := &serviceScanWriter{cancel: cancel, path: filepath.Join(filepath.Dir(c.OutputDir), "watched", "app.conf")}
	if err := Serve(ctx, c, w, "test"); err != nil {
		t.Fatal(err)
	}
	if w.scans != 2 || !strings.Contains(w.log.String(), `"kind":"modified"`) || strings.Contains(w.log.String(), "inspection_error") {
		t.Fatalf("service reset on each scan or failed startup: scans=%d logs=%s", w.scans, w.log.String())
	}
}
