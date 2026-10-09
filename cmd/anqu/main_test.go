package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anqu/internal/audit"
)

func TestAgentRejectsExternalConfigWithoutLoadingPayload(t *testing.T) {
	for _, args := range [][]string{{"-config", "secret.yaml"}, {"-check-config"}, {"secret.yaml"}, {"-dump-config"}, {"-once"}} {
		var stdout, stderr bytes.Buffer
		loaded := false
		code := run(args, &stdout, &stderr, func() ([]byte, error) { loaded = true; return nil, nil }, os.Executable)
		if code != 1 || loaded || strings.Contains(stderr.String(), "secret.yaml") {
			t.Fatalf("args=%v code=%d loaded=%t stderr=%s", args, code, loaded, stderr.String())
		}
	}
}

func TestAgentHelpAndVersionDoNotLoadConfig(t *testing.T) {
	for _, arg := range []string{"-help", "-version"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{arg}, &stdout, &stderr, func() ([]byte, error) { t.Fatal("must not decrypt config"); return nil, nil }, os.Executable)
		if code != 0 {
			t.Fatalf("%s failed", arg)
		}
		if arg == "-version" && stdout.String() != "anqu "+version+"\n" {
			t.Fatal("unexpected version output")
		}
	}
}

func TestAgentErrorsDoNotPrintConfiguration(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		data := []byte("private_secret_field: 'PRIVATE_CONFIG_MARKER'\n")
		code := run(nil, &stdout, &stderr, func() ([]byte, error) {
			if invalid {
				return data, nil
			}
			return nil, errors.New("decryption failed PRIVATE_CONFIG_MARKER")
		}, func() (string, error) { return filepath.Join(t.TempDir(), "anqu"), nil })
		if code != 1 || stderr.Len() != 0 || stdout.Len() != 0 {
			t.Fatalf("sensitive runtime error: %s %s", stdout.String(), stderr.String())
		}
		if invalid && !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("decrypted source not cleared after parse failure")
		}
	}
}

func TestAgentUsesExecutableDirectoryWithoutConfigFile(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	data := []byte("output_dir: output\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\n")
	code := run(nil, &stdout, &stderr, func() ([]byte, error) { return data, nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "output", "textfile", "anqu.prom")); err != nil {
		t.Fatal(err)
	}
	logs, err := filepath.Glob(filepath.Join(dir, "output", "logs", "*.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs=%v err=%v", logs, err)
	}
	logData, err := os.ReadFile(logs[0])
	if err != nil || !bytes.Contains(logData, []byte(`"event":"agent_started"`)) || !bytes.Contains(logData, []byte(`"event":"scan_complete"`)) {
		t.Fatalf("local lifecycle logs missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("agent wrote or required a YAML configuration file")
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("decrypted YAML source not cleared")
	}
}

func TestAgentFindingsExitTwoAndPreserveRealPathsInReports(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	data := []byte("output_dir: output\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  base_dir: watched\n  files:\n    - path: missing.conf\n")
	code := run(nil, &stdout, &stderr, func() ([]byte, error) { return data, nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
	if code != 2 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	reports, err := filepath.Glob(filepath.Join(dir, "output", "*.json"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports=%v err=%v", reports, err)
	}
	b, err := os.ReadFile(reports[0])
	if err != nil || !strings.Contains(string(b), "missing.conf") {
		t.Fatalf("real path absent from findings: %v", err)
	}
}

func TestAgentEachInvocationUsesCurrentConfigAndFreshBaseline(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"first.conf", "second.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for step, name := range []string{"first.conf", "second.conf", "second.conf"} {
		var stdout, stderr bytes.Buffer
		config := "output_dir: output\nFilesMonitoring:\n  fils: [" + name + "]\nlogin:\n  enabled: false\nsetup:\n  logs: logs/agent.log\n  prom: collector/agent.prom\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat(name, step+1)), 0600); err != nil {
			t.Fatal(err)
		}
		code := run(nil, &stdout, &stderr, func() ([]byte, error) { return []byte(config), nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
		if code != 0 {
			t.Fatalf("fresh invocation rejected config/current content: code=%d stderr=%s", code, stderr.String())
		}
	}
	reports, err := filepath.Glob(filepath.Join(dir, "output", "*.json"))
	if err != nil || len(reports) != 3 {
		t.Fatalf("missing reports: %v %v", reports, err)
	}
	for _, path := range reports {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var report audit.Report
		if err := json.Unmarshal(data, &report); err != nil || !report.Files.BaselineCreated || len(report.Files.Changes) != 0 {
			t.Fatalf("invocation reused previous lifetime baseline: %+v %v", report.Files, err)
		}
	}
}
