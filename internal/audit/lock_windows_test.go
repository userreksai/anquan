//go:build windows

package audit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsLockReleasedAfterProcessKilled(t *testing.T) {
	const helperPathEnv = "ANQU_TEST_LOCK_HELPER_PATH"
	if path := os.Getenv(helperPathEnv); path != "" {
		release, err := lockState(path)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		fmt.Println("lock acquired")
		for {
			time.Sleep(time.Hour)
		}
	}

	path := filepath.Join(t.TempDir(), "state.service.lock")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsLockReleasedAfterProcessKilled$")
	cmd.Env = append(os.Environ(), helperPathEnv+"="+path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "lock acquired" {
		t.Fatalf("child did not acquire lock: %q (scan error: %v)", scanner.Text(), scanner.Err())
	}
	if release, err := lockState(path); err == nil {
		release()
		t.Fatal("lock acquired while another process held it")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected forced child termination")
	}

	// Windows may take a short time to release locks after terminating a process.
	deadline := time.Now().Add(5 * time.Second)
	for {
		release, err := lockState(path)
		if err == nil {
			release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forced termination left a stale lock: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWindowsLockReleaseIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.service.lock")
	firstRelease, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	firstRelease()
	secondRelease, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	firstRelease()
	if release, err := lockState(path); err == nil {
		release()
		t.Fatal("releasing an old lock allowed a concurrent run")
	}
}
