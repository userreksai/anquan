//go:build linux

package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"anqu/internal/security"
)

func nativeStartLinuxTest(t *testing.T, c Config) (<-chan security.Event, <-chan error, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan security.Event, 128)
	errors := make(chan error, 32)
	ready := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		nativeFIMLoop(ctx, c, func(e security.Event) error { events <- e; return nil }, func(err error) {
			if err != nil {
				errors <- err
			}
			select {
			case ready <- struct{}{}:
			default:
			}
		})
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("watcher did not initialize")
	}
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("watcher did not stop")
		}
	}
	return events, errors, stop
}

func nativeNextLinuxEvent(t *testing.T, events <-chan security.Event, errors <-chan error) security.Event {
	t.Helper()
	select {
	case e := <-events:
		return e
	case err := <-errors:
		t.Fatalf("native watcher: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("native lifecycle event timed out")
	}
	return security.Event{}
}

func TestNativeFIMLinuxScriptExecutionRemovalAndEditorNoise(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.PollIntervalSeconds = 60 // proves the real-time path
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	swap := filepath.Join(root, ".123.sh.swp")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(swap, []byte{byte(i)}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	os.Remove(swap)
	p := filepath.Join(root, "123.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nprintf first"), 0700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	text := "#!/bin/sh\nprintf recorded"
	if err := os.WriteFile(p, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	added := nativeNextLinuxEvent(t, events, errors)
	d := nativeFIMDetails(t, added)
	if added.Data["path"] != p || added.Data["kind"] != "file_change" || d["change"] != "added" || d["current_text"] != text {
		t.Fatalf("unexpected creation/noise: %+v", added)
	}
	if out, err := exec.Command("sh", p).CombinedOutput(); err != nil || string(out) != "recorded" {
		t.Fatalf("execute: %q %v", out, err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	deleted := nativeNextLinuxEvent(t, events, errors)
	d = nativeFIMDetails(t, deleted)
	if deleted.Data["path"] != p || d["change"] != "deleted" || d["previous_text"] != text {
		t.Fatalf("deleted evidence: %+v", deleted)
	}
	select {
	case e := <-events:
		t.Fatalf("duplicate/noise notification: %+v", e)
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(350 * time.Millisecond):
	}
}

func TestNativeFIMLinuxImmediateRemovalStillRecordsObservedLifecycle(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	p := filepath.Join(root, "instant.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	added := nativeNextLinuxEvent(t, events, errors)
	deleted := nativeNextLinuxEvent(t, events, errors)
	a, d := nativeFIMDetails(t, added), nativeFIMDetails(t, deleted)
	if a["change"] != "added" || d["change"] != "deleted" {
		t.Fatalf("missing short-lived transitions: %+v / %+v", a, d)
	}
	if status := a["current_content_status"]; status != "unavailable" && status != "captured" {
		t.Fatalf("misleading vanished content: %+v", a)
	}
	if status := d["previous_content_status"]; status != a["current_content_status"] {
		t.Fatalf("deletion lost capture status: %+v", d)
	}
}

func TestNativeFIMLinuxMovedDirectoryDoesNotDisableRecreatedPath(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	c.Security.NativeFIM.PollIntervalSeconds = 60
	events, errors, stop := nativeStartLinuxTest(t, c)
	defer stop()
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	// Wait for the directory event to install its new child watch, then use
	// real-time capture with the periodic scanner deliberately far in the future.
	time.Sleep(100 * time.Millisecond)
	p := filepath.Join(a, "inside.sh")
	text := "#!/bin/sh\ntrue\n"
	if err := os.WriteFile(p, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case e := <-events:
			if e.Data["path"] == p {
				d := nativeFIMDetails(t, e)
				if d["current_text"] != text || d["change"] != "added" {
					t.Fatalf("recreated directory content: %+v", e)
				}
				return
			}
		case err := <-errors:
			t.Fatal(err)
		case <-deadline.C:
			t.Fatal("recreated path lost its watch")
		}
	}
}
