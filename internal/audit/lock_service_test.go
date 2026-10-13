package audit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestServiceLockScopesResourcesWithoutLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "config.master.age")
	state := filepath.Join(dir, "agent.state")
	release, err := lockService(cache)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if unlock, err := lockService(cache); err == nil {
		unlock()
		t.Fatal("concurrent service lock accepted")
	}
	unlockState, err := lockService(state)
	if err != nil {
		t.Fatalf("cache and state locks in one directory interfered: %v", err)
	}
	unlockState()
	if _, err := os.Stat(cache + ".service.lock"); !os.IsNotExist(err) {
		t.Fatalf("obsolete service lock file exists: %v", err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("lock created or changed the protected configuration file: %v", err)
	}
	before, err := os.Stat(serviceLockDirectory(cache))
	if err != nil || !before.IsDir() {
		t.Fatalf("service lock does not use a directory: %v", err)
	}
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir(serviceLockDirectory(cache))
		if err != nil || len(entries) != 0 {
			t.Fatalf("Linux service lock created regular files: %v %v", entries, err)
		}
	}
	release()
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		after, err := os.Stat(serviceLockDirectory(cache))
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("service lock removed or replaced its stable directory: %v", err)
		}
	}
	reacquired, err := lockService(cache)
	if err != nil {
		t.Fatalf("released service lock cannot be reacquired: %v", err)
	}
	defer reacquired()
	// An old release must not affect a newly acquired lock.
	release()
	if unlock, err := lockService(cache); err == nil {
		unlock()
		t.Fatal("releasing an old service lock allowed a concurrent run")
	}
}

func TestServiceLockReleasedAfterProcessKilled(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("forced termination cleanup requires an OS lock")
	}
	const helperPathEnv = "ANQU_TEST_SERVICE_LOCK_HELPER_PATH"
	if path := os.Getenv(helperPathEnv); path != "" {
		release, err := lockService(path)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		fmt.Println("lock acquired")
		for {
			time.Sleep(time.Hour)
		}
	}
	path := filepath.Join(t.TempDir(), "config.master.age")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceLockReleasedAfterProcessKilled$")
	cmd.Env = append(os.Environ(), helperPathEnv+"="+path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "lock acquired" {
		t.Fatalf("child did not acquire service lock: %q (%v)", scanner.Text(), scanner.Err())
	}
	if release, err := lockService(path); err == nil {
		release()
		t.Fatal("service lock acquired while another process held it")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected forced child termination")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		release, err := lockService(path)
		if err == nil {
			release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forced termination left a stale service lock: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
