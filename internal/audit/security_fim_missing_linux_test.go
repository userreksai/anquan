//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"anqu/internal/security"
)

func nativeAssertLinuxQuiet(t *testing.T, events <-chan security.Event, errors <-chan error) {
	t.Helper()
	select {
	case e := <-events:
		t.Fatalf("unexpected or repeated native event: %+v", e)
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(350 * time.Millisecond):
	}
}

func nativeAssertLinuxChanges(t *testing.T, events <-chan security.Event, errors <-chan error, change string, paths ...string) {
	t.Helper()
	wanted := map[string]bool{}
	for _, p := range paths {
		wanted[p] = true
	}
	for range paths {
		e := nativeNextLinuxEvent(t, events, errors)
		p, _ := e.Data["path"].(string)
		if !wanted[p] || e.Data["kind"] != "file_change" || e.Data["severity"] != "warning" || nativeFIMDetails(t, e)["change"] != change {
			t.Fatalf("wanted one %s for %v, got %+v", change, paths, e)
		}
		delete(wanted, p)
	}
	nativeAssertLinuxQuiet(t, events, errors)
}

func TestNativeFIMLinuxInitiallyMissingFileIsSilentUntilCreation(t *testing.T) {
	c := securityTestConfig(t)
	p := filepath.Join(t.TempDir(), "cron.allow")
	c.Security.NativeFIM.Paths = []string{p}
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	nativeAssertLinuxQuiet(t, events, errors)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("optional file was created by discovery: %v", err)
	}
	if err := os.WriteFile(p, []byte("ubuntu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", p)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "deleted", p)
	if err := os.WriteFile(p, []byte("ec2-user\n"), 0600); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", p)
}

func TestNativeFIMLinuxMissingAncestorsDiscoverPopulatedTreeAndRecreation(t *testing.T) {
	c := securityTestConfig(t)
	root := filepath.Join(t.TempDir(), "later", "spool", "cron")
	c.Security.NativeFIM.Paths = []string{root}
	c.Security.NativeFIM.PollIntervalSeconds = 60
	// Build a populated tree before it enters the watched path. None of its
	// children can generate IN_CREATE on a child watch that does not yet exist.
	staging := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(filepath.Join(staging, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(staging, "job-a"), filepath.Join(staging, "nested", "job-b")} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	nativeAssertLinuxQuiet(t, events, errors)
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, root); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested")
	a, b := filepath.Join(root, "job-a"), filepath.Join(nested, "job-b")
	nativeAssertLinuxChanges(t, events, errors, "added", root, nested, a, b)
	// Subsequent changes inside that tree must use its newly installed watches.
	late := filepath.Join(nested, "late-job")
	if err := os.WriteFile(late, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", late)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "deleted", root, nested, a, b, late)
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("#!/bin/sh\necho recreated\n"), 0700); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", root, nested, b)
}

func TestNativeFIMLinuxDirectoryPermissionChangesRemainVisible(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	nativeAssertLinuxQuiet(t, events, errors)
	if err := os.Chmod(root, 0750); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "modified", root)
}

func TestNativeFIMLinuxOwnershipChangesRemainVisible(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	c, root := nativeFIMTestRoot(t)
	p := filepath.Join(root, "job")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	nativeAssertLinuxQuiet(t, events, errors)
	if err := os.Chown(p, 65534, 65534); err != nil {
		t.Skipf("host does not permit ownership changes: %v", err)
	}
	nativeAssertLinuxChanges(t, events, errors, "modified", p)
}

func TestNativeFIMLinuxMovedOutTreeDoesNotKeepOldPathWatches(t *testing.T) {
	c := securityTestConfig(t)
	base := t.TempDir()
	root := filepath.Join(base, "cron")
	nested := filepath.Join(root, "nested", "deeper")
	job := filepath.Join(nested, "job")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(job, []byte("#!/bin/sh\necho original\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c.Security.NativeFIM.Paths = []string{root}
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	nativeAssertLinuxQuiet(t, events, errors)
	moved := filepath.Join(base, "moved-outside-scope")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "deleted", root, filepath.Dir(nested), nested, job)
	// Those inodes still exist, but their paths are no longer in scope. A
	// leftover descendant watch used to misreport these writes at the old path.
	movedNested := filepath.Join(moved, "nested", "deeper")
	if err := os.WriteFile(filepath.Join(movedNested, "job"), []byte("#!/bin/sh\necho outside\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(movedNested, "outside-job"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxQuiet(t, events, errors)
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(job, []byte("#!/bin/sh\necho recreated\n"), 0700); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", root, filepath.Dir(nested), nested, job)
	late := filepath.Join(nested, "late-job")
	if err := os.WriteFile(late, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
		t.Fatal(err)
	}
	nativeAssertLinuxChanges(t, events, errors, "added", late)
}
