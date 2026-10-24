package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"anqu/internal/security"
)

func TestNativeFIMInitiallyMissingRootLifecycleAcrossRestart(t *testing.T) {
	c := securityTestConfig(t)
	p := filepath.Join(t.TempDir(), "cron.allow")
	c.Security.NativeFIM.Paths = []string{p}
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	poll := func() {
		t.Helper()
		if err := pollNativeFIM(context.Background(), NewSession(c), emit); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	poll()
	if len(events) != 0 {
		t.Fatalf("initial absence was reported: %+v", events)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("discovery created an optional root: %v", err)
	}
	_, state, unlock, err := nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	if state.Files[p].Type != "missing" || len(state.Roots) != 1 || state.Sequence != 0 {
		t.Fatalf("absence was not retained as a silent baseline: %+v", state)
	}
	unlock()
	for _, want := range []string{"added", "deleted", "added"} {
		if want == "deleted" {
			err = os.Remove(p)
		} else {
			err = os.WriteFile(p, []byte("ubuntu\n"), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		prior := len(events)
		poll()
		if len(events) != prior+1 || events[prior].Data["severity"] != "warning" || nativeFIMDetails(t, events[prior])["change"] != want {
			t.Fatalf("wanted one %s transition: %+v", want, events[prior:])
		}
		poll()
		if len(events) != prior+1 {
			t.Fatalf("unchanged %s state repeated: %+v", want, events[prior:])
		}
	}
}

func TestNativeFIMNewMissingRootPreservesExistingBaseline(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	existing := filepath.Join(root, "existing")
	if err := os.WriteFile(existing, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error {
		t.Fatalf("initial baseline was not silent: %+v", e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	optional := filepath.Join(t.TempDir(), "cron.deny")
	c.Security.NativeFIM.Paths = append(c.Security.NativeFIM.Paths, optional)
	if err := os.WriteFile(existing, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	var events []security.Event
	if err := pollNativeFIM(context.Background(), NewSession(c), func(e security.Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Data["path"] != existing || nativeFIMDetails(t, events[0])["change"] != "modified" {
		t.Fatalf("new optional root reset or polluted the old baseline: %+v", events)
	}
}

func TestNativeFIMLegacyMissingBaselineKeepsGenerationAndSequence(t *testing.T) {
	c := securityTestConfig(t)
	p := filepath.Join(t.TempDir(), "cron.allow")
	c.Security.NativeFIM.Paths = []string{p}
	state := nativeFIMState{Version: 1, Generation: "legacy-generation", Sequence: 12, Roots: []string{p}, Files: map[string]nativeFile{p: {Type: "missing"}}}
	statePath := filepath.Join(securityDataDir(c), "native-fim.state")
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeState(statePath, "security-fim", state); err != nil {
		t.Fatal(err)
	}
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("legacy absence repeated after upgrade: %+v", events)
	}
	if err := os.WriteFile(p, []byte("ubuntu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pollNativeFIM(context.Background(), NewSession(c), emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "native-fim:legacy-generation:13" || nativeFIMDetails(t, events[0])["change"] != "added" {
		t.Fatalf("legacy identity/baseline was reset: %+v", events)
	}
}

func TestNativeFIMMissingRootRepeatedDeleteIsSilent(t *testing.T) {
	c := securityTestConfig(t)
	p := filepath.Join(t.TempDir(), "cron.allow")
	c.Security.NativeFIM.Paths = []string{p}
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error {
		t.Fatalf("initial absence was not silent: %+v", e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		events := nativeAtomicApply(t, c, nativeFIMObservation{Path: p, Observed: true})
		if len(events) != 0 {
			t.Fatalf("a known absent root was deleted again: %+v", events)
		}
	}
}

func TestNativeFIMNewDirectoryLifecycleIncludesChildren(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	poll := func() {
		t.Helper()
		if err := pollNativeFIM(context.Background(), c, emit); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	dir := filepath.Join(root, "cron.daily")
	child := filepath.Join(dir, "job")
	for _, want := range []string{"added", "deleted", "added"} {
		if want == "deleted" {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(child, []byte("#!/bin/sh\ntrue\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		events = nil
		poll()
		got := map[string]int{}
		for _, e := range events {
			if e.Data["severity"] != "warning" || nativeFIMDetails(t, e)["change"] != want {
				t.Fatalf("unexpected directory transition: %+v", e)
			}
			got[e.Data["path"].(string)]++
		}
		if len(events) != 2 || got[dir] != 1 || got[child] != 1 {
			t.Fatalf("directory/child %s evidence missing or repeated: %+v", want, events)
		}
		events = nil
		poll()
		if len(events) != 0 {
			t.Fatalf("directory/child state repeated: %+v", events)
		}
	}
}
