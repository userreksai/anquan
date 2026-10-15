package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"anqu/internal/audit"
	"anqu/internal/install"
)

func TestInstalledNoArgumentSSHUsesServiceBeforeConfigOrScan(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.50 54321 192.0.2.10 22")
	seen := map[string]bool{}
	for range 2 {
		var stdout, stderr bytes.Buffer
		code := runPreparedWithSSH(nil, &stdout, &stderr,
			func() ([]byte, error) { t.Fatal("SSH hook read root-only config"); return nil, nil },
			func() (string, error) { return install.Executable, nil },
			func(string, []string, io.Writer) (install.Preparation, error) {
				t.Fatal("SSH hook attempted installation or full audit")
				return install.Preparation{}, nil
			},
			func(ctx context.Context, base string, req audit.SSHExecutionRequest) error {
				if _, ok := ctx.Deadline(); !ok || req.Connection != "192.0.2.50 54321 192.0.2.10 22" || len(req.ID) != 32 || seen[req.ID] {
					t.Fatalf("invocation did not carry its own bounded request: %+v", req)
				}
				seen[req.ID] = true
				return nil
			},
			func() (audit.SSHExecutionCaller, error) {
				t.Fatal("successful IPC fell back")
				return audit.SSHExecutionCaller{}, nil
			}, func(string) bool { return true })
		if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("SSH hook failed: %d %q %q", code, stdout.String(), stderr.String())
		}
	}
	if len(seen) != 2 {
		t.Fatal("two invocations did not produce two independent requests")
	}
}

func TestFreshUploadAtFixedPathStillInstalls(t *testing.T) {
	var stdout, stderr bytes.Buffer
	prepared := false
	code := runPreparedWithSSH(nil, &stdout, &stderr,
		func() ([]byte, error) { t.Fatal("install-only loaded configuration"); return nil, nil },
		func() (string, error) { return install.Executable, nil },
		func(string, []string, io.Writer) (install.Preparation, error) {
			prepared = true
			return install.Preparation{Path: install.Executable, InstallOnly: true}, nil
		},
		func(context.Context, string, audit.SSHExecutionRequest) error {
			t.Fatal("fresh upload attempted SSH reporting")
			return nil
		},
		func() (audit.SSHExecutionCaller, error) {
			t.Fatal("fresh upload attempted SSH fallback")
			return audit.SSHExecutionCaller{}, nil
		},
		func(string) bool { return false })
	if code != 0 || !prepared {
		t.Fatalf("fresh fixed-path upload did not install: %d %q", code, stderr.String())
	}
}

func TestSSHServiceRejectionDoesNotRetryOrReadConfiguration(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.50 54321 192.0.2.10 22")
	var stderr bytes.Buffer
	calls := 0
	code := reportSSHExecution(install.Executable, "", &stderr,
		func() ([]byte, error) { t.Fatal("service rejection read configuration"); return nil, nil },
		func(context.Context, string, audit.SSHExecutionRequest) error {
			calls++
			return errors.New("login disabled")
		},
		func() (audit.SSHExecutionCaller, error) {
			t.Fatal("service rejection retried locally")
			return audit.SSHExecutionCaller{}, nil
		})
	if code != 1 || calls != 1 || stderr.Len() == 0 {
		t.Fatalf("service rejection was not visible: %d %d %q", code, calls, stderr.String())
	}
}

func TestNonRootUnavailableSSHServiceDoesNotReadConfig(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.50 54321 192.0.2.10 22")
	var stderr bytes.Buffer
	code := reportSSHExecution(install.Executable, "", &stderr,
		func() ([]byte, error) { t.Fatal("non-root fallback read configuration"); return nil, nil },
		func(context.Context, string, audit.SSHExecutionRequest) error {
			return audit.ErrSSHExecutionUnavailable
		},
		func() (audit.SSHExecutionCaller, error) {
			return audit.SSHExecutionCaller{UID: 1000, Username: "ubuntu"}, nil
		})
	if code != 1 || stderr.Len() == 0 {
		t.Fatalf("missing service was silently accepted: %d %q", code, stderr.String())
	}
}

func TestRootUnavailableSSHServiceReportsFromExistingConfiguration(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.50 54321 192.0.2.10 22")
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	base := t.TempDir()
	record := audit.LoginRecord{ID: "original", User: "ubuntu", SourceIP: "192.0.2.50", SourcePort: 54321, Terminal: "N/A", LoginTime: time.Now().Add(-time.Hour).UTC()}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(base, "login.jsonl"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	yaml := []byte("output_dir: output\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin: {enabled: true, source: jsonl, path: login.jsonl}\nserver: ['" + listener.LocalAddr().String() + "']\nsetup: {logs: logs/agent.log, prom: collector/agent.prom}\n")
	var stderr bytes.Buffer
	code := reportSSHExecution(filepath.Join(base, "anquan"), "", &stderr,
		func() ([]byte, error) { return append([]byte(nil), yaml...), nil },
		func(context.Context, string, audit.SSHExecutionRequest) error {
			return audit.ErrSSHExecutionUnavailable
		},
		func() (audit.SSHExecutionCaller, error) {
			return audit.SSHExecutionCaller{UID: 0, Username: "root"}, nil
		})
	if code != 0 {
		t.Fatalf("root fallback failed: %d %q", code, stderr.String())
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65536)
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Type string            `json:"type"`
		Data audit.LoginRecord `json:"data"`
	}
	if err := json.Unmarshal(buf[:n], &event); err != nil || event.Type != "ssh_login" || event.Data.ID == record.ID || event.Data.Trigger != "execution" || !event.Data.LoginTime.Equal(record.LoginTime) || event.Data.User != "ubuntu" || event.Data.ExecutedBy != "root" {
		t.Fatalf("root fallback lost original authentication: %+v %v", event, err)
	}
}
