package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRejectsExternalConfigWithoutLoadingPayload(t *testing.T) {
	for _, args := range [][]string{{"-config", "secret.yaml"}, {"-check-config"}, {"secret.yaml"}, {"-dump-config"}} {
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
		if code != 1 || strings.Contains(stderr.String(), "PRIVATE_CONFIG_MARKER") || stdout.Len() != 0 {
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
