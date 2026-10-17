package security

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

const tetragonVersionQuery = "tetra --server-address unix:///var/run/tetragon/tetragon.sock --timeout 2s --retries 0 version --server"

type versionCommandResult struct {
	output string
	err    error
}

type versionStatusRunner struct {
	calls   []string
	results map[string][]versionCommandResult
	missing map[string]bool
	paths   map[string]string
}

func (r *versionStatusRunner) LookPath(name string) (string, error) {
	if r.missing[name] {
		return "", os.ErrNotExist
	}
	if path := r.paths[name]; path != "" {
		return path, nil
	}
	return name, nil
}

func (r *versionStatusRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	command := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if results := r.results[command]; len(results) > 0 {
		result := results[0]
		r.results[command] = results[1:]
		return result.output, result.err
	}
	if name == "systemctl" && len(args) == 3 && args[0] == "is-active" && args[1] == "--quiet" {
		return "", nil
	}
	return "", errors.New("unexpected command: " + command)
}

func (r *versionStatusRunner) count(command string) int {
	n := 0
	for _, call := range r.calls {
		if call == command {
			n++
		}
	}
	return n
}

func newVersionStatusManager(t *testing.T, r *versionStatusRunner) *Manager {
	t.Helper()
	m := NewManager(Config{}, t.TempDir())
	m.Runner = r
	return m
}

func TestTetragonServerVersion(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{"server rather than cli", "CLI version: v1.7.0\nServer version: v1.7.1\n", "v1.7.1"},
		{"crlf", "CLI version: v1.7.0\r\nServer version: v1.7.1\r\n", "v1.7.1"},
		{"without v prefix", "Server version: 1.7.1\n", "1.7.1"},
		{"prerelease and build", "Server version: v1.8.0-pre.0+build.2\n", "v1.8.0-pre.0+build.2"},
		{"empty", "", ""},
		{"cli only", "CLI version: v1.7.1\n", ""},
		{"unknown flag", "Error: unknown flag: --version\n", ""},
		{"server error", "CLI version: v1.7.1\nServer version: Error: connection refused\n", ""},
		{"devel", "Server version: (devel)\n", ""},
		{"incomplete version", "Server version: v1.7\n", ""},
		{"prefixed log text", "error retrieving Server version: v1.7.1\n", ""},
		{"trailing error", "Server version: v1.7.1 connection failed\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tetragonServerVersion(tc.output); got != tc.want {
				t.Fatalf("tetragonServerVersion(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

func TestTetragonBuildVersion(t *testing.T) {
	const versionSetting = "github.com/cilium/tetragon/pkg/version.Version="
	cases := []struct {
		name    string
		module  string
		version string
		flags   string
		want    string
	}{
		{"released main module", "github.com/cilium/tetragon", "v1.7.1", "", "v1.7.1"},
		{"released without v prefix", "github.com/cilium/tetragon", "1.7.1", "", "1.7.1"},
		{"released prerelease", "github.com/cilium/tetragon", "v1.8.0-pre.0+build.2", "", "v1.8.0-pre.0+build.2"},
		{"official single quotes", "github.com/cilium/tetragon", "(devel)", "-X '" + versionSetting + "v1.7.1' -X 'github.com/cilium/tetragon/pkg/version.Name=tetragon' -s -w", "v1.7.1"},
		{"double quotes", "github.com/cilium/tetragon", "(devel)", "-X \"" + versionSetting + "v1.7.1\"", "v1.7.1"},
		{"unquoted", "github.com/cilium/tetragon", "(devel)", "-s -w -X " + versionSetting + "v1.7.1", "v1.7.1"},
		{"equals form", "github.com/cilium/tetragon", "(devel)", "-X=" + versionSetting + "v1.7.1", "v1.7.1"},
		{"quoted equals form", "github.com/cilium/tetragon", "(devel)", "-X='" + versionSetting + "v1.7.1'", "v1.7.1"},
		{"devel without setting", "github.com/cilium/tetragon", "(devel)", "", ""},
		{"empty version", "github.com/cilium/tetragon", "", "", ""},
		{"unrelated module", "example.com/other", "v1.7.1", "", ""},
		{"incomplete module version", "github.com/cilium/tetragon", "v1.7", "", ""},
		{"unrelated variable", "github.com/cilium/tetragon", "(devel)", "-X example.com/other.Version=v1.7.1", ""},
		{"setting requires X flag", "github.com/cilium/tetragon", "(devel)", versionSetting + "v1.7.1", ""},
		{"setting devel", "github.com/cilium/tetragon", "(devel)", "-X '" + versionSetting + "(devel)'", ""},
		{"setting error text", "github.com/cilium/tetragon", "(devel)", "-X '" + versionSetting + "Error: unknown flag: --version'", ""},
		{"setting incomplete version", "github.com/cilium/tetragon", "(devel)", "-X '" + versionSetting + "v1.7'", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &debug.BuildInfo{
				Path: "github.com/cilium/tetragon/cmd/tetragon",
				Main: debug.Module{Path: tc.module, Version: tc.version},
			}
			if tc.flags != "" {
				info.Settings = []debug.BuildSetting{{Key: "-ldflags", Value: tc.flags}}
			}
			if got := tetragonBuildVersion(info); got != tc.want {
				t.Fatalf("tetragonBuildVersion(%+v) = %q, want %q", info, got, tc.want)
			}
		})
	}
	if got := tetragonBuildVersion(nil); got != "" {
		t.Fatalf("nil build information returned %q", got)
	}
}

func TestStatusTetragonUsesServerVersionAndCachesSuccess(t *testing.T) {
	r := &versionStatusRunner{results: map[string][]versionCommandResult{
		tetragonVersionQuery: {{output: "CLI version: v1.6.1\nServer version: v1.7.1\n"}},
	}}
	m := newVersionStatusManager(t, r)
	for i := 0; i < 2; i++ {
		status := m.status(context.Background(), "tetragon", true)
		if status.Version != "v1.7.1" || !status.Installed || !status.Running || status.State != "running" {
			t.Fatalf("status %d = %+v", i, status)
		}
	}
	if got := r.count(tetragonVersionQuery); got != 1 {
		t.Fatalf("version queried %d times, want successful result cached; calls=%v", got, r.calls)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "tetragon ") {
			t.Fatalf("version query must not execute the Tetragon daemon: %s", call)
		}
	}
}

func TestStatusTetragonRetriesUnusableVersion(t *testing.T) {
	cases := []struct {
		name  string
		first versionCommandResult
	}{
		{"command error", versionCommandResult{output: "Error: unknown flag: --version\n", err: errors.New("exit status 1")}},
		{"command error despite version line", versionCommandResult{output: "Server version: v1.7.0\n", err: errors.New("exit status 1")}},
		{"empty", versionCommandResult{}},
		{"cli only on rpc error", versionCommandResult{output: "CLI version: v1.7.0\nError: connection refused\n"}},
		{"invalid server version", versionCommandResult{output: "CLI version: v1.7.0\nServer version: Error: connection refused\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &versionStatusRunner{results: map[string][]versionCommandResult{
				tetragonVersionQuery: {tc.first, {output: "CLI version: v1.7.0\nServer version: v1.7.1\n"}},
			}}
			m := newVersionStatusManager(t, r)
			status := m.status(context.Background(), "tetragon", true)
			if status.Version != "" || !status.Running || status.State != "running" {
				t.Fatalf("failed version query corrupted service status: %+v", status)
			}
			if version, ok := m.versions["tetragon"]; ok {
				t.Fatalf("unusable version was cached: %q", version)
			}
			for i := 0; i < 2; i++ {
				status = m.status(context.Background(), "tetragon", true)
				if status.Version != "v1.7.1" || !status.Running {
					t.Fatalf("version did not recover: %+v", status)
				}
			}
			if got := r.count(tetragonVersionQuery); got != 2 {
				t.Fatalf("version queried %d times, want one retry then success cached; calls=%v", got, r.calls)
			}
		})
	}
}

func TestStatusTetragonWithoutCLILeavesVersionUnknown(t *testing.T) {
	r := &versionStatusRunner{missing: map[string]bool{"tetra": true}}
	m := newVersionStatusManager(t, r)
	status := m.status(context.Background(), "tetragon", true)
	if status.Version != "" || !status.Installed || !status.Running {
		t.Fatalf("missing CLI should not prevent independent daemon health check: %+v", status)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "tetra ") || strings.HasPrefix(call, "tetragon ") {
			t.Fatalf("missing CLI must not cause a daemon execution: %s", call)
		}
	}
}

func TestStatusTetragonFallsBackToInstalledBinaryBuildInfo(t *testing.T) {
	moduleDir := t.TempDir()
	versionDir := filepath.Join(moduleDir, "pkg", "version")
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":                 "module github.com/cilium/tetragon\n\ngo 1.25.0\n",
		"main.go":                "package main\n\nimport \"github.com/cilium/tetragon/pkg/version\"\n\nfunc main() { println(version.Version) }\n",
		"pkg/version/version.go": "package version\n\nvar Version = \"(devel)\"\n",
	}
	for path, source := range files {
		if err := os.WriteFile(filepath.Join(moduleDir, filepath.FromSlash(path)), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goName := "go"
	binaryName := "tetragon"
	if runtime.GOOS == "windows" {
		goName += ".exe"
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(moduleDir, binaryName)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", goName), "build", "-ldflags", "-X 'github.com/cilium/tetragon/pkg/version.Version=v1.7.1' -s -w", "-o", binaryPath, ".")
	build.Dir = moduleDir
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build version fixture: %v\n%s", err, output)
	}
	for _, missingCLI := range []bool{true, false} {
		name := "rpc failure"
		if missingCLI {
			name = "cli missing"
		}
		t.Run(name, func(t *testing.T) {
			r := &versionStatusRunner{
				paths:   map[string]string{"tetragon": binaryPath},
				missing: map[string]bool{"tetra": missingCLI},
				results: map[string][]versionCommandResult{
					tetragonVersionQuery: {{output: "CLI version: v1.6.1\nError: connection refused\n", err: errors.New("exit status 1")}},
				},
			}
			m := newVersionStatusManager(t, r)
			for i := 0; i < 2; i++ {
				status := m.status(context.Background(), "tetragon", true)
				if status.Version != "v1.7.1" || !status.Installed || !status.Running {
					t.Fatalf("installed binary version was not reported: %+v", status)
				}
			}
			wantQueries := 1
			if missingCLI {
				wantQueries = 0
			}
			if got := r.count(tetragonVersionQuery); got != wantQueries {
				t.Fatalf("CLI queried %d times, want %d; calls=%v", got, wantQueries, r.calls)
			}
			for _, call := range r.calls {
				if strings.HasPrefix(call, binaryPath+" ") || strings.HasPrefix(call, "tetragon ") {
					t.Fatalf("fallback must read the binary without executing it: %s", call)
				}
			}
		})
	}
}

func TestStatusVersionQueryHonorsCancellation(t *testing.T) {
	r := &versionStatusRunner{}
	m := newVersionStatusManager(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	status := m.status(ctx, "tetragon", true)
	if time.Since(start) > time.Second {
		t.Fatal("version query ignored caller cancellation")
	}
	if status.Version != "" {
		t.Fatalf("cancelled query produced version %q", status.Version)
	}
	if version, ok := m.versions["tetragon"]; ok {
		t.Fatalf("cancelled query cached %q", version)
	}
	if len(r.calls) != 0 {
		t.Fatalf("cancelled context reached active command calls: %v", r.calls)
	}
}

func TestStatusOtherComponentVersionsRetryFailures(t *testing.T) {
	cases := []struct {
		name    string
		command string
		version string
	}{
		{"auditd", "auditctl -v", "auditctl version 3.1.2"},
		{"sudo", "sudo --version", "Sudo version 1.9.15p5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &versionStatusRunner{results: map[string][]versionCommandResult{
				tc.command: {
					{output: "Error: version query failed\n", err: errors.New("exit status 1")},
					{output: tc.version + "\nAdditional version details\n"},
				},
			}}
			m := newVersionStatusManager(t, r)
			if status := m.status(context.Background(), tc.name, true); status.Version != "" || !status.Running {
				t.Fatalf("failed version query corrupted component state: %+v", status)
			}
			if version, ok := m.versions[tc.name]; ok {
				t.Fatalf("failed query cached %q", version)
			}
			for i := 0; i < 2; i++ {
				if status := m.status(context.Background(), tc.name, true); status.Version != tc.version || !status.Running {
					t.Fatalf("version did not recover: %+v", status)
				}
			}
			if got := r.count(tc.command); got != 2 {
				t.Fatalf("queried %d times, want failure retry and successful cache; calls=%v", got, r.calls)
			}
		})
	}
}
