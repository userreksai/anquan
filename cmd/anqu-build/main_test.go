package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadYAMLRejectsJSONAndOversize(t *testing.T) {
	for _, tc := range []struct {
		name, filename, content string
	}{
		{"json extension", "config.json", "{\"output_dir\":\"/tmp\"}"},
		{"json renamed yaml", "config.yaml", "{\"output_dir\":\"/tmp\"}"},
		{"json renamed with BOM", "config.yaml", "\xef\xbb\xbf {\"output_dir\":\"/tmp\"}"},
		{"empty", "config.yml", " \n\t"},
		{"too large", "config.yaml", strings.Repeat("#", maxConfigBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readYAML(path); err == nil {
				t.Fatal("invalid build input accepted")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("# retain original bytes\noutput_dir: /usr/local/anqu\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readYAML(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("valid YAML roundtrip = %q, %v", got, err)
	}
}

func TestBuildEnvironmentOverrides(t *testing.T) {
	result := buildEnv([]string{"PATH=keep", "GOOS=darwin", "gocache=unsafe", "GOFLAGS=-x", "GOCACHEPROG=external-helper", "GOENV=private-env"}, map[string]string{
		"GOOS": "linux", "GOCACHE": "private", "GOFLAGS": "", "GOCACHEPROG": "", "GOENV": "off",
	})
	joined := strings.Join(result, "\n")
	for _, unwanted := range []string{"GOOS=darwin", "gocache=unsafe", "GOFLAGS=-x", "GOCACHEPROG=external-helper", "GOENV=private-env"} {
		if strings.Contains(joined, unwanted) {
			t.Fatalf("inherited unsafe environment: %s", joined)
		}
	}
	for _, wanted := range []string{"PATH=keep", "GOOS=linux", "GOCACHE=private", "GOFLAGS="} {
		if !strings.Contains(joined, wanted) {
			t.Fatalf("missing environment setting %q", wanted)
		}
	}
}

func TestFailedBuildPreservesExistingOutputAndCleansStaging(t *testing.T) {
	temp := t.TempDir()
	config := filepath.Join(temp, "config.yaml")
	if err := os.WriteFile(config, []byte("output_dir: /usr/local/anqu\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(temp, "existing-agent")
	if err := os.WriteFile(output, []byte("old agent"), 0755); err != nil {
		t.Fatal(err)
	}
	// A fake compiler performs no shell execution. It records arguments and
	// fails so we can verify cleanup and preservation without compiling Go.
	helper := filepath.Join(temp, "fake-go")
	if runtime.GOOS == "windows" {
		helper += ".exe"
	}
	compiler := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		compiler += ".exe"
	}
	helperSource := filepath.Join(temp, "fake.go")
	source := `package main
import("encoding/json"; "os")
func main(){ b,_:=json.Marshal(os.Args); _=os.WriteFile(os.Getenv("ANQU_BUILD_TEST_CAPTURE"),b,0600); os.Exit(7) }
`
	if err := os.WriteFile(helperSource, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(compiler, "build", "-o", helper, helperSource)
	cmd.Env = buildEnv(os.Environ(), map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": "0"})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test compiler: %v\n%s", err, out)
	}
	capture := filepath.Join(temp, "args.json")
	t.Setenv("ANQU_BUILD_TEST_CAPTURE", capture)
	err := build(options{config: config, output: output, goos: "linux", goarch: "amd64", goCommand: helper}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "compile agent") {
		t.Fatalf("expected compiler error, got %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "old agent" {
		t.Fatalf("existing output damaged: %q, %v", got, err)
	}
	args, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var recorded []string
	if err := json.Unmarshal(args, &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded[len(recorded)-1] != "./cmd/anqu" {
		t.Fatal("wrong compiler target")
	}
	staged, err := filepath.Glob(filepath.Join(temp, ".anqu-output-*"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staging outputs remain: %v, %v", staged, err)
	}
}

func TestOutputCannotReplaceConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("output_dir: /tmp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectConfigOutput(path, path); err == nil {
		t.Fatal("configuration overwrite accepted")
	}
}

func TestArgumentValidation(t *testing.T) {
	for _, args := range [][]string{{"unexpected"}, {"-does-not-exist"}} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Fatalf("invalid args accepted: %v", args)
		}
	}
	if err := run([]string{"-help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if root, err := projectRoot(); err != nil || root == "" {
		t.Fatal(fmt.Sprintf("locate source = %q, %v", root, err))
	}
}
