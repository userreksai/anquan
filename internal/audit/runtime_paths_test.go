package audit

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstalledAgentUsesSystemRuntimeOnlyOnLinux(t *testing.T) {
	base := filepath.Clean(installedAgentDirectory)
	wantSocket := filepath.Join(base, ".ssh-execution", "agent.sock")
	if runtime.GOOS == "linux" {
		wantSocket = filepath.Join(systemAgentRuntimeDirectory, ".ssh-execution", "agent.sock")
	}
	if got := SSHExecutionSocket(base); got != wantSocket {
		t.Fatalf("installed socket path %q, want %q", got, wantSocket)
	}
	for _, relative := range []string{"config.master.age", filepath.Join("state", "md5.json"), filepath.Join("other", "md5.json")} {
		resource := filepath.Join(base, relative)
		wantLock := filepath.Join(filepath.Dir(resource), ".anqu-service-locks", filepath.Base(resource))
		if runtime.GOOS == "linux" {
			wantLock = filepath.Join(systemAgentRuntimeDirectory, ".anqu-service-locks", relative)
		}
		if got := serviceLockDirectory(resource); got != wantLock {
			t.Fatalf("installed lock path %q, want %q", got, wantLock)
		}
	}
}

func TestCustomAndAdjacentDeploymentsKeepLocalRuntimePaths(t *testing.T) {
	for _, base := range []string{t.TempDir(), installedAgentDirectory + "-custom", filepath.Join(installedAgentDirectory, "..", "outside")} {
		resource := filepath.Join(base, "config.master.age")
		wantLock := filepath.Join(filepath.Dir(resource), ".anqu-service-locks", filepath.Base(resource))
		if got := serviceLockDirectory(resource); got != wantLock {
			t.Fatalf("custom lock path %q, want %q", got, wantLock)
		}
		wantSocket := filepath.Join(base, ".ssh-execution", "agent.sock")
		if got := SSHExecutionSocket(base); got != wantSocket {
			t.Fatalf("custom socket path %q, want %q", got, wantSocket)
		}
	}
}
