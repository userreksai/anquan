package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func jsonPut(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	put(t, path, string(b))
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	put(t, filepath.Join(root, "watched", "app.conf"), "initial\n")
	put(t, filepath.Join(root, "login.jsonl"), "{\"source_ip\":\"192.0.2.1\",\"login_time\":\"2026-10-01T08:00:00+08:00\",\"user\":\"ops\",\"terminal\":\"pts/1\"}\n")
	jsonPut(t, filepath.Join(root, "files.json"), []CheckEntry{{Path: "app.conf", Type: "file"}})
	c := Config{
		OutputDir: "output", StateFile: "state/md5.json", Timezone: "Asia/Shanghai",
		MD5:       MD5Config{Enabled: true, Paths: []string{"watched"}, Recursive: true},
		Login:     LoginConfig{Enabled: true, Source: "jsonl", Path: "login.jsonl", LastCommand: "last", TimeoutSeconds: 10, MaxRecords: 1000},
		Existence: ExistenceConfig{Enabled: true, ListFile: "files.json", BaseDir: "watched"},
	}
	path := filepath.Join(root, "config.json")
	jsonPut(t, path, c)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func runOK(t *testing.T, c Config) (Report, OutputPaths) {
	t.Helper()
	r, paths, err := Run(c)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Success {
		t.Fatalf("collection failed: %+v", r.Errors)
	}
	return r, paths
}

func TestLifecycleAndOutput(t *testing.T) {
	c := testConfig(t)
	root := c.MD5.Paths[0]
	put(t, filepath.Join(root, "deleted.conf"), "remove me")
	r, paths := runOK(t, c)
	if !r.MD5.BaselineCreated || r.MD5.Scanned != 2 || len(r.MD5.Changes) != 0 {
		t.Fatalf("bad initial baseline: %+v", r.MD5)
	}
	if filepath.Dir(paths.Prom) != c.OutputDir || filepath.Base(paths.Latest) != "anqu.prom" {
		t.Fatal("wrong output paths")
	}
	if read(t, paths.Prom) != read(t, paths.Latest) {
		t.Fatal("archive and latest metrics differ")
	}
	var decoded Report
	if err := readJSON(paths.JSON, &decoded); err != nil || !decoded.Success {
		t.Fatalf("invalid report: %v", err)
	}
	if decoded.Login.Record.User != "ops" || decoded.Login.Record.Terminal != "pts/1" {
		t.Fatal("missing login details")
	}
	put(t, filepath.Join(root, "app.conf"), "changed and longer\n")
	put(t, filepath.Join(root, "added.conf"), "new file\n")
	if err := os.Remove(filepath.Join(root, "deleted.conf")); err != nil {
		t.Fatal(err)
	}
	r, paths = runOK(t, c)
	want := map[string]bool{"added": false, "modified": false, "deleted": false}
	for _, change := range r.MD5.Changes {
		want[change.Kind] = true
		if change.Kind == "modified" && (change.Before == "" || change.After == "" || change.Before == change.After) {
			t.Fatal("wrong before/after hashes")
		}
	}
	if len(r.MD5.Changes) != 3 {
		t.Fatalf("expected three changes: %+v", r.MD5.Changes)
	}
	for kind, found := range want {
		if !found || r.MD5.Cumulative[kind] != 1 {
			t.Fatalf("missing %s", kind)
		}
	}
	if !strings.Contains(read(t, paths.Prom), "anqu_md5_changes_total{kind=\"modified\"} 1\n") {
		t.Fatal("missing persisted counter")
	}
	r, _ = runOK(t, c)
	if r.MD5.BaselineCreated || len(r.MD5.Changes) != 0 || r.MD5.Cumulative["modified"] != 1 || r.MD5.LastChange == nil {
		t.Fatalf("baseline not advanced: %+v", r.MD5)
	}
	archives, err := filepath.Glob(filepath.Join(c.OutputDir, "*.prom"))
	if err != nil || len(archives) != 3 {
		t.Fatalf("history lost: %v %v", archives, err)
	}
	latest, _ := filepath.Glob(filepath.Join(c.OutputDir, "textfile", "*.prom"))
	if len(latest) != 1 {
		t.Fatal("duplicate latest metrics")
	}
}

func TestHashKnownValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	put(t, path, "abc")
	hash, err := hashFile(path)
	if err != nil || hash != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("hash=%s err=%v", hash, err)
	}
}

func TestRecursionExclusionsAndOwnOutput(t *testing.T) {
	c := testConfig(t)
	root := c.MD5.Paths[0]
	c.OutputDir = filepath.Join(root, "output")
	c.StateFile = filepath.Join(c.OutputDir, "state", "md5.json")
	c.MD5.ExcludePaths = []string{filepath.Join(root, "skip")}
	put(t, filepath.Join(root, "skip", "secret"), "skip")
	put(t, filepath.Join(root, "child", "nested"), "nested")
	r, _ := runOK(t, c)
	if r.MD5.Scanned != 2 {
		t.Fatalf("bad recursive scan: %+v", r.MD5)
	}
	r, _ = runOK(t, c)
	if len(r.MD5.Changes) != 0 || r.MD5.Scanned != 2 {
		t.Fatal("program monitored its own output")
	}
	c2 := testConfig(t)
	c2.MD5.Recursive = false
	put(t, filepath.Join(c2.MD5.Paths[0], "child", "nested"), "nested")
	r, _ = runOK(t, c2)
	if r.MD5.Scanned != 1 {
		t.Fatal("recursive=false scanned nested files")
	}
}

func TestBaselineFailurePreservesState(t *testing.T) {
	t.Run("scope-change", func(t *testing.T) {
		c := testConfig(t)
		runOK(t, c)
		before := read(t, c.StateFile)
		c.MD5.Recursive = false
		r, paths, err := Run(c)
		if err != nil || r.Success || r.MD5.Success {
			t.Fatalf("expected module failure: %+v %v", r, err)
		}
		if read(t, c.StateFile) != before {
			t.Fatal("overwrote baseline after scope change")
		}
		prom := read(t, paths.Latest)
		if !strings.Contains(prom, "anqu_collection_success 0\n") || strings.Contains(prom, "anqu_md5_changes{") {
			t.Fatal("failure presented as zero changes")
		}
	})
	t.Run("corrupt-state", func(t *testing.T) {
		c := testConfig(t)
		put(t, c.StateFile, "{broken")
		r, _, err := Run(c)
		if err != nil || r.Success || r.MD5.BaselineCreated || read(t, c.StateFile) != "{broken" {
			t.Fatal("corrupt state silently replaced")
		}
	})
	t.Run("first-root-missing", func(t *testing.T) {
		c := testConfig(t)
		c.MD5.Paths = []string{filepath.Join(c.Existence.BaseDir, "absent")}
		r, _, err := Run(c)
		if err != nil || r.Success {
			t.Fatal("initial missing root accepted")
		}
		if _, err := os.Stat(c.StateFile); !os.IsNotExist(err) {
			t.Fatal("baseline created for failed scan")
		}
	})
}

func TestOutputFailureDoesNotConsumeChanges(t *testing.T) {
	c := testConfig(t)
	_, paths := runOK(t, c)
	before := read(t, c.StateFile)
	if err := os.Remove(paths.Latest); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.Latest, 0755); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(c.MD5.Paths[0], "app.conf"), "changed")
	if _, _, err := Run(c); err == nil {
		t.Fatal("expected publication error")
	}
	if read(t, c.StateFile) != before {
		t.Fatal("baseline advanced before publication")
	}
	if err := os.Remove(paths.Latest); err != nil {
		t.Fatal(err)
	}
	r, _ := runOK(t, c)
	if len(r.MD5.Changes) != 1 || r.MD5.Cumulative["modified"] != 1 {
		t.Fatal("change was lost or double-counted")
	}
}

func TestMissingRootAfterBaselineIsDeletion(t *testing.T) {
	c := testConfig(t)
	runOK(t, c)
	root := c.MD5.Paths[0]
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	r, _ := runOK(t, c)
	if len(r.MD5.MissingRoots) != 1 || len(r.MD5.Changes) != 1 || r.MD5.Changes[0].Kind != "deleted" || r.Existence.Missing != 1 {
		t.Fatalf("missing root not reported: %+v", r)
	}
}

func TestExistenceTypesAndMissing(t *testing.T) {
	c := testConfig(t)
	jsonPut(t, c.Existence.ListFile, []CheckEntry{
		{Path: "app.conf", Type: "file"}, {Path: "absent", Type: "file"},
		{Path: ".", Type: "file"}, {Path: "child", Type: "directory"},
	})
	if err := os.Mkdir(filepath.Join(c.Existence.BaseDir, "child"), 0755); err != nil {
		t.Fatal(err)
	}
	r, _ := runOK(t, c)
	if r.Existence.Missing != 1 || r.Existence.TypeMismatch != 1 || len(r.Existence.Items) != 4 {
		t.Fatalf("bad existence result: %+v", r.Existence)
	}
}

func TestJSONLLatestAndErrors(t *testing.T) {
	newer := `{"source_ip":"2001:db8::1","login_time":"2026-10-01T10:00:00+08:00","user":"newer","terminal":"pts/2"}`
	older := `{"source_ip":"192.0.2.1","login_time":"2026-10-01T01:59:59Z","user":"older","terminal":"pts/0"}`
	r, err := parseJSONL(strings.NewReader("\xef\xbb\xbf" + newer + "\n\n" + older + "\n"))
	if err != nil || r == nil || r.User != "newer" {
		t.Fatalf("wrong latest login: %+v %v", r, err)
	}
	if r, err := parseJSONL(strings.NewReader("\n")); err != nil || r != nil {
		t.Fatal("empty source must have no record")
	}
	for _, invalid := range []string{"{broken", strings.Replace(newer, "2001:db8::1", "not-an-ip", 1), strings.Replace(newer, "pts/2", "", 1)} {
		if _, err := parseJSONL(strings.NewReader(newer + "\n" + invalid)); err == nil {
			t.Fatal("corrupt latest data silently ignored")
		}
	}
}

func TestParseLast(t *testing.T) {
	text := "reboot system boot 6.8.0 2026-10-01T03:00:00+00:00 still running\n" +
		"alice-long-name pts/2 2001:db8::1 2026-10-01T02:00:00+00:00 still logged in\n" +
		"bob pts/0 192.0.2.4 2026-10-01T01:00:00+00:00 - 2026-10-01T01:10:00+00:00 (00:10)\n"
	r, err := parseLast(text)
	if err != nil || r.User != "alice-long-name" || r.Terminal != "pts/2" || r.SourceIP != "2001:db8::1" {
		t.Fatalf("bad last parse: %+v %v", r, err)
	}
	for _, line := range []string{"root tty1 0.0.0.0 2026-10-01T02:00:00+00:00 still logged in", "root tty1 2026-10-01T02:00:00+00:00 still logged in"} {
		r, err := parseLast(line)
		if err != nil || r.SourceIP != "" {
			t.Fatalf("local login: %+v %v", r, err)
		}
	}
	if r, err := parseLast("\nwtmp begins 2026-10-01T02:00:00+00:00\n"); err != nil || r != nil {
		t.Fatal("footer parsed as login")
	}
	if _, err := parseLast("root pts/0 host Thu Oct 1 10:00"); err == nil {
		t.Fatal("invalid format accepted")
	}
}

func TestLoginErrorDoesNotSuppressOtherModules(t *testing.T) {
	c := testConfig(t)
	put(t, c.Login.Path, "{broken")
	r, paths, err := Run(c)
	if err != nil || r.Success || r.Login.Success || !r.MD5.Success || !r.Existence.Success {
		t.Fatalf("wrong partial result: %+v %v", r, err)
	}
	if strings.Contains(read(t, paths.Latest), "anqu_login_found ") {
		t.Fatal("failed login represented as empty source")
	}
	if _, err := os.Stat(c.StateFile); err != nil {
		t.Fatal("successful MD5 module did not commit")
	}
}

func TestMetricLabels(t *testing.T) {
	value := "C:\\etc\\a\"b\nc\t配置"
	if got, want := label(value), "\"C:\\\\etc\\\\a\\\"b\\nc\t配置\""; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	r := Report{StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0), Success: true,
		Login: LoginResult{Enabled: true, Success: true, Record: &LoginRecord{User: value, Terminal: "pts/0", LoginTime: time.Unix(100, 0)}}}
	out := string(metrics(r))
	if !strings.Contains(out, "anqu_last_login_timestamp_seconds 100\n") || !strings.Contains(out, "user="+label(value)) {
		t.Fatal("bad metric values")
	}
}

func TestConfigRejectsInvalidInputs(t *testing.T) {
	for _, name := range []string{"unknown-field", "duplicate-check", "relative-escape", "empty-checks", "invalid-timezone", "excluded-root", "multiple-json-values"} {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			path := filepath.Join(filepath.Dir(c.OutputDir), "config.json")
			switch name {
			case "unknown-field":
				put(t, path, `{"typo":true}`)
			case "duplicate-check":
				jsonPut(t, c.Existence.ListFile, []CheckEntry{{Path: "app.conf"}, {Path: "app.conf"}})
			case "relative-escape":
				jsonPut(t, c.Existence.ListFile, []CheckEntry{{Path: "../escape"}})
			case "empty-checks":
				put(t, c.Existence.ListFile, "[]")
			case "invalid-timezone":
				c.Timezone = "Invalid/Zone"
				jsonPut(t, path, c)
			case "excluded-root":
				c.MD5.Paths = []string{c.OutputDir}
				jsonPut(t, path, c)
			case "multiple-json-values":
				put(t, path, read(t, path)+"\n{}")
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestLockExcludesConcurrentRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := lockState(path); err == nil {
		release()
		unlock()
		t.Fatal("concurrent lock accepted")
	}
	unlock()
	release, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestDisabledModules(t *testing.T) {
	c := testConfig(t)
	c.MD5.Enabled, c.Login.Enabled, c.Existence.Enabled = false, false, false
	r, paths := runOK(t, c)
	if r.Login.Record != nil || r.MD5.Scanned != 0 || len(r.Existence.Items) != 0 {
		t.Fatal("disabled module ran")
	}
	if strings.Contains(read(t, paths.Latest), "anqu_md5_changes{") {
		t.Fatal("disabled MD5 exported result")
	}
	if _, err := os.Stat(c.StateFile); !os.IsNotExist(err) {
		t.Fatal("disabled MD5 created baseline")
	}
}
