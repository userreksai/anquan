package security

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const aptListsBusy = "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 108100 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/"

type aptLockRunner struct {
	run   func(context.Context, string, ...string) (string, error)
	calls int
}

func (r *aptLockRunner) LookPath(name string) (string, error) { return name, nil }
func (r *aptLockRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls++
	return r.run(ctx, name, args...)
}

func TestAPTLockBusyOnlyRecognizesExplicitContention(t *testing.T) {
	for _, output := range []string{
		aptListsBusy,
		"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 123 (unattended-upgr)",
		"E: Could not get lock /var/lib/dpkg/lock - open (11: Resource temporarily unavailable)",
		"E: Could not get lock /var/cache/apt/archives/lock - open (11: Resource temporarily unavailable)",
	} {
		if !aptLockBusy(output) {
			t.Errorf("missed busy lock: %s", output)
		}
	}
	for _, output := range []string{
		"E: Could not get lock /var/lib/apt/lists/lock - open (13: Permission denied)",
		"E: Could not get lock /var/lib/dpkg/lock-frontend - open (30: Read-only file system)",
		"E: Unable to lock directory /var/lib/apt/lists/",
		"E: Could not get lock /tmp/unrelated/lock. It is held by process 123 (other)",
		"E: Could not get lock /var/lib/dpkg/lock-frontend-other. It is held by process 123 (other)",
		"E: Could not get lock /var/lib/apt/lists/lock.\nIt is held by process 123 (other)",
		"E: Could not get lock /var/lib/apt/lists/lock - open (13: Permission denied)\nE: Resource temporarily unavailable",
		"Err:1 http://archive.ubuntu.com/ubuntu noble InRelease Connection timed out",
		"E: The repository is not signed.",
		"E: Unable to correct problems, you have held broken packages.",
		"E: Failed to fetch package: master package relay disabled",
	} {
		if aptLockBusy(output) {
			t.Errorf("classified unrelated failure as contention: %s", output)
		}
	}
}

func TestAPTLockRetryKeepsRelayArgumentsAndNormalCommandDeadline(t *testing.T) {
	for _, operation := range []string{"update", "install"} {
		t.Run(operation, func(t *testing.T) {
			args := []string{"-o", "Acquire::http::Proxy=http://127.0.0.1:46539", "-o", "Acquire::https::Proxy=http://127.0.0.1:46539", operation}
			want := append([]string{"-o", "DPkg::Lock::Timeout=0"}, args...)
			ctx := relayCommandContext(context.Background(), "http://127.0.0.1:46539")
			runner := &aptLockRunner{}
			runner.run = func(gotCtx context.Context, name string, gotArgs ...string) (string, error) {
				if name != "apt-get" || !reflect.DeepEqual(gotArgs, want) {
					t.Fatalf("relay arguments changed: %s %v", name, gotArgs)
				}
				if _, ok := gotCtx.Deadline(); ok {
					t.Fatal("lock wait budget shortened normal command deadline")
				}
				if gotCtx.Value(downloadEnvironmentKey{}) != ctx.Value(downloadEnvironmentKey{}) {
					t.Fatal("relay environment context was dropped")
				}
				if runner.calls == 1 {
					return aptListsBusy, errors.New("exit status 100")
				}
				return "installed", nil
			}
			output, err := runAPTWithLockRetry(ctx, runner, time.Second, time.Millisecond, args...)
			if err != nil || output != "installed" || runner.calls != 2 {
				t.Fatalf("retry did not recover: output=%q calls=%d err=%v", output, runner.calls, err)
			}
		})
	}
}

func TestAPTLockRetryReturnsNonLockFailuresImmediately(t *testing.T) {
	for _, failure := range []string{
		"E: Could not get lock /var/lib/apt/lists/lock - open (13: Permission denied)",
		"E: Could not get lock /var/lib/dpkg/lock - open (30: Read-only file system)",
		"E: Failed to fetch package: Connection timed out",
		"E: The repository is not signed.",
		"E: Unable to correct problems, you have held broken packages.",
		"E: Failed to fetch package: master package relay disabled",
	} {
		cause := errors.New(failure)
		runner := &aptLockRunner{run: func(context.Context, string, ...string) (string, error) { return failure, cause }}
		output, err := runAPTWithLockRetry(context.Background(), runner, time.Minute, time.Second, "update")
		if !errors.Is(err, cause) || output != failure || runner.calls != 1 {
			t.Errorf("unexpected retry or changed error: calls=%d output=%q err=%v", runner.calls, output, err)
		}
	}
}

func TestAPTLockRetryBudgetExpiresWithHolderDetails(t *testing.T) {
	cause := errors.New("exit status 100")
	runner := &aptLockRunner{run: func(context.Context, string, ...string) (string, error) { return aptListsBusy, cause }}
	output, err := runAPTWithLockRetry(context.Background(), runner, 10*time.Millisecond, time.Minute, "update")
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "timed out waiting") || !strings.Contains(err.Error(), "process 108100 (apt-get)") || output != aptListsBusy {
		t.Fatalf("timeout lost underlying lock error: output=%q err=%v", output, err)
	}
	if runner.calls != 1 {
		t.Fatalf("command ran again after the lock wait budget expired: calls=%d", runner.calls)
	}
}

func TestAPTLockRetryCancellationStopsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	runner := &aptLockRunner{run: func(context.Context, string, ...string) (string, error) {
		close(started)
		return aptListsBusy, errors.New("exit status 100")
	}}
	finished := make(chan error, 1)
	go func() {
		_, err := runAPTWithLockRetry(ctx, runner, time.Minute, time.Minute, "update")
		finished <- err
	}()
	<-started
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || runner.calls != 1 {
			t.Fatalf("cancellation retried or returned wrong error: calls=%d err=%v", runner.calls, err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt lock wait")
	}
}

func TestAPTLockRetryCancellationTakesPrecedenceOverCommandError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &aptLockRunner{run: func(context.Context, string, ...string) (string, error) {
		cancel()
		return "", errors.New("signal: killed")
	}}
	_, err := runAPTWithLockRetry(ctx, runner, time.Minute, time.Second, "update")
	if !errors.Is(err, context.Canceled) || runner.calls != 1 {
		t.Fatalf("context cancellation was hidden: calls=%d err=%v", runner.calls, err)
	}
	_, err = runAPTWithLockRetry(ctx, runner, time.Minute, time.Second, "update")
	if !errors.Is(err, context.Canceled) || runner.calls != 1 {
		t.Fatalf("already canceled context started a command: calls=%d err=%v", runner.calls, err)
	}
}

func TestEnsurePackageRetriesBothAPTUpdateAndInstallLocks(t *testing.T) {
	m, runner := testManager(t, Config{InstallMissing: true})
	runner.missing["auditctl"] = true
	attempts := map[string]int{}
	runner.fail = func(name string, args []string) error {
		if name != "apt-get" {
			return nil
		}
		joined := strings.Join(args, " ")
		operation := "update"
		if strings.Contains(joined, "install -y --no-install-recommends auditd") {
			operation = "install"
		}
		attempts[operation]++
		if attempts[operation] == 1 {
			return errors.New(aptListsBusy)
		}
		if operation == "install" {
			runner.missing["auditctl"] = false
		}
		return nil
	}
	if err := m.ensurePackage(context.Background(), "auditctl", "auditd", "audit"); err != nil {
		t.Fatal(err)
	}
	if attempts["update"] != 2 || attempts["install"] != 2 {
		t.Fatalf("both APT operations must retry: %v", attempts)
	}
}
