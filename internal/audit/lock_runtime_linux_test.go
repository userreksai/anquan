//go:build linux

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func lockRuntimeTestDirectory(t *testing.T, path string) func() {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockLinuxFile(f, "test-resource")
	if err != nil {
		t.Fatal(err)
	}
	return unlock
}

func TestRuntimeServiceLockCoordinatesWithExistingLegacyProcess(t *testing.T) {
	base := sshIPCBase(t)
	current, legacy := filepath.Join(base, "runtime"), filepath.Join(base, "legacy")
	for _, path := range []string{current, legacy} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldUnlock := lockRuntimeTestDirectory(t, legacy)
	defer oldUnlock()
	if unlock, err := lockServiceDirectories("test-resource", current, legacy); !errors.Is(err, errStateLockBusy) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("runtime lock ignored the old service: %v", err)
	}
	// Failing to acquire the old lock must release the new one.
	lockRuntimeTestDirectory(t, current)()
	oldUnlock()
	unlock, err := lockServiceDirectories("test-resource", current, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for _, path := range []string{current, legacy} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if release, err := lockLinuxFile(f, "test-resource"); !errors.Is(err, errStateLockBusy) {
			if release != nil {
				release()
			}
			t.Fatalf("runtime service did not retain %s: %v", path, err)
		}
	}
	unlock()
	for _, path := range []string{current, legacy} {
		lockRuntimeTestDirectory(t, path)()
	}
}

func TestRuntimeServiceLockDoesNotCreateLegacyDirectory(t *testing.T) {
	current := sshIPCBase(t)
	legacy := filepath.Join(current, "missing-legacy")
	unlock, err := lockServiceDirectories("test-resource", current, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("runtime lock recreated the obsolete directory: %v", err)
	}
}

func TestRuntimeServiceLockPreservesInvalidLegacyEntryAndReleasesNewLock(t *testing.T) {
	base := sshIPCBase(t)
	current := filepath.Join(base, "runtime")
	if err := os.Mkdir(current, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(base, "legacy")
	if err := os.WriteFile(legacy, []byte("preserve me"), 0600); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockServiceDirectories("test-resource", current, legacy); err == nil {
		unlock()
		t.Fatal("invalid legacy entry accepted")
	}
	data, err := os.ReadFile(legacy)
	if err != nil || string(data) != "preserve me" {
		t.Fatalf("invalid legacy entry changed: %q, %v", data, err)
	}
	lockRuntimeTestDirectory(t, current)()
}
