//go:build linux

package audit

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func sshIPCBase(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned IPC lifecycle requires Linux root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func waitSSHExecutionSocket(t *testing.T, baseDir string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(SSHExecutionSocket(baseDir)); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("IPC listener stopped before ready: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("IPC listener did not become ready")
}

func TestSSHExecutionIPCReportsEachInvocationAndPreservesBusinessErrors(t *testing.T) {
	base := sshIPCBase(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var ids []string
	reporter := func(_ context.Context, _ Config, _ io.Writer, req SSHExecutionRequest, caller SSHExecutionCaller) (LoginRecord, error) {
		if caller.UID != uint32(os.Geteuid()) || caller.PID != os.Getpid() || caller.Username == "" {
			return LoginRecord{}, errors.New("wrong kernel caller")
		}
		mu.Lock()
		ids = append(ids, req.ID)
		mu.Unlock()
		if req.ID == "disabled" {
			return LoginRecord{}, errors.New("SSH login reporting is disabled")
		}
		return LoginRecord{}, nil
	}
	done := make(chan error, 1)
	go func() { done <- serveSSHExecutionsWithReporter(ctx, Config{runtimeDir: base}, io.Discard, reporter) }()
	waitSSHExecutionSocket(t, base, done)
	for _, id := range []string{"first", "second"} {
		if err := RequestSSHExecution(ctx, base, SSHExecutionRequest{ID: id, Connection: "127.0.0.1 1234 127.0.0.1 22"}); err != nil {
			t.Fatal(err)
		}
	}
	err := RequestSSHExecution(ctx, base, SSHExecutionRequest{ID: "disabled"})
	if err == nil || !strings.Contains(err.Error(), "reporting is disabled") || errors.Is(err, ErrSSHExecutionUnavailable) {
		t.Fatalf("business error lost or permits fallback: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(ids, ",") != "first,second,disabled" {
		t.Fatalf("invocations coalesced or repeated: %v", ids)
	}
	if _, err := os.Lstat(SSHExecutionSocket(base)); !os.IsNotExist(err) {
		t.Fatalf("listener socket remains after shutdown: %v", err)
	}
}

func TestSSHExecutionIPCCancellationClosesReadersAndJoinsReports(t *testing.T) {
	base := sshIPCBase(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	finished := make(chan struct{})
	reporter := func(ctx context.Context, _ Config, _ io.Writer, _ SSHExecutionRequest, _ SSHExecutionCaller) (LoginRecord, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return LoginRecord{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- serveSSHExecutionsWithReporter(ctx, Config{runtimeDir: base}, io.Discard, reporter) }()
	waitSSHExecutionSocket(t, base, done)
	idle, err := net.Dial("unix", SSHExecutionSocket(base))
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	requestDone := make(chan error, 1)
	go func() {
		requestDone <- RequestSSHExecution(context.Background(), base, SSHExecutionRequest{ID: "blocked"})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("reporter did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not close blocked connections")
	}
	select {
	case <-finished:
	default:
		t.Fatal("server returned before reporter joined")
	}
	if err := <-requestDone; err == nil || errors.Is(err, ErrSSHExecutionUnavailable) {
		t.Fatalf("accepted request cancellation permits direct retry: %v", err)
	}
}

func TestSSHExecutionSocketProtectsLiveFileAndSymlinkAndRecoversStale(t *testing.T) {
	base := sshIPCBase(t)
	listener, info, err := listenSSHExecutions(base)
	if err != nil {
		t.Fatal(err)
	}
	path := SSHExecutionSocket(base)
	if socket, err := os.Lstat(path); err != nil || socket.Mode().Perm() != 0666 || !sshExecutionRootOwned(socket) {
		t.Fatalf("socket permissions/owner are wrong: %v, %v", socket, err)
	}
	if dir, err := os.Lstat(filepath.Dir(path)); err != nil || dir.Mode().Perm() != 0755 || !sshExecutionRootOwned(dir) {
		t.Fatalf("runtime directory permissions/owner are wrong: %v, %v", dir, err)
	}
	if _, _, err := listenSSHExecutions(base); err == nil || !strings.Contains(err.Error(), "active listener") {
		t.Fatalf("live listener not protected: %v", err)
	}
	_ = listener.Close() // Explicit cleanup leaves a stale socket for recovery.
	listener, info, err = listenSSHExecutions(base)
	if err != nil {
		t.Fatalf("stale socket not recovered: %v", err)
	}
	_ = listener.Close()
	removeOwnSSHExecutionSocket(path, info)
	if err := os.WriteFile(path, []byte("preserve me"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listenSSHExecutions(base); err == nil {
		t.Fatal("regular file was removed")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "preserve me" {
		t.Fatalf("regular file changed: %q %v", data, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listenSSHExecutions(base); err == nil {
		t.Fatal("socket symlink was followed")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("socket symlink was changed: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "target" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}
}

func TestSSHExecutionUnavailableOnlyBeforeRequestAccepted(t *testing.T) {
	base := sshIPCBase(t)
	if err := RequestSSHExecution(context.Background(), base, SSHExecutionRequest{ID: "missing"}); !errors.Is(err, ErrSSHExecutionUnavailable) {
		t.Fatalf("missing socket not classified: %v", err)
	}
	listener, _, err := listenSSHExecutions(base)
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if err := RequestSSHExecution(context.Background(), base, SSHExecutionRequest{ID: "stale"}); !errors.Is(err, ErrSSHExecutionUnavailable) {
		t.Fatalf("refused socket not classified: %v", err)
	}
}

func TestSSHExecutionIPCUsesUnprivilegedKernelCaller(t *testing.T) {
	base := sshIPCBase(t)
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody account not available")
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	gid, _ := strconv.ParseUint(account.Gid, 10, 32)
	if err := os.Chmod(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(base, "ipc-client-test")
	if err := os.WriteFile(child, data, 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter := func(_ context.Context, _ Config, _ io.Writer, _ SSHExecutionRequest, caller SSHExecutionCaller) (LoginRecord, error) {
		if caller.UID != uint32(uid) || caller.PID == os.Getpid() || caller.Username != account.Username {
			return LoginRecord{}, fmtSSHCallerError(caller)
		}
		return LoginRecord{}, nil
	}
	done := make(chan error, 1)
	go func() { done <- serveSSHExecutionsWithReporter(ctx, Config{runtimeDir: base}, io.Discard, reporter) }()
	waitSSHExecutionSocket(t, base, done)
	command := exec.Command(child, "-test.run=^TestSSHExecutionIPCUnprivilegedClientHelper$")
	command.Env = append(os.Environ(), "ANQUAN_IPC_TEST_CLIENT=1", "ANQUAN_IPC_TEST_BASE="+base)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged IPC failed: %v: %s", err, output)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func fmtSSHCallerError(caller SSHExecutionCaller) error {
	return errors.New("unexpected unprivileged kernel caller: " + caller.Username + ":" + strconv.FormatUint(uint64(caller.UID), 10))
}

func TestSSHExecutionIPCUnprivilegedClientHelper(t *testing.T) {
	if os.Getenv("ANQUAN_IPC_TEST_CLIENT") != "1" {
		t.Skip("subprocess helper")
	}
	if err := RequestSSHExecution(context.Background(), os.Getenv("ANQUAN_IPC_TEST_BASE"), SSHExecutionRequest{ID: "unprivileged"}); err != nil {
		t.Fatal(err)
	}
}
