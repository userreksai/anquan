package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"anqu/internal/security"
)

func nativeAtomicFixture(t *testing.T) (Config, string, string) {
	t.Helper()
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.ReportChanges = true
	p := filepath.Join(root, "config.sh")
	const original = "#!/bin/sh\necho original\n"
	if err := os.WriteFile(p, []byte(original), 0700); err != nil {
		t.Fatal(err)
	}
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error { t.Fatalf("initial baseline emitted event: %+v", e); return nil }); err != nil {
		t.Fatal(err)
	}
	return c, p, original
}

func nativeAtomicWrite(t *testing.T, c Config, path, text string) *nativeFile {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	n, err := nativeReadFile(context.Background(), path, c.Security.NativeFIM, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if n.ContentStatus != "captured" {
		t.Fatalf("fixture capture unavailable: %+v", n)
	}
	return &n
}

func nativeAtomicApply(t *testing.T, c Config, observations ...nativeFIMObservation) []security.Event {
	t.Helper()
	var events []security.Event
	accepted, err := nativeApplyObservations(c, observations, func(e security.Event) error { events = append(events, e); return nil })
	if !accepted || err != nil {
		t.Fatalf("batch not accepted: %v %v", accepted, err)
	}
	return events
}

func nativeAssertAtomicModification(t *testing.T, events []security.Event, path, before, after string) {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("expected one modification, got %d: %+v", len(events), events)
	}
	e := events[0]
	d := nativeFIMDetails(t, e)
	if e.Data["path"] != path || e.Data["kind"] != "file_change" || d["change"] != "modified" || d["previous_text"] != before || d["current_text"] != after {
		t.Fatalf("atomic replacement lost before/final after: %+v", e)
	}
}

func TestNativeFIMAtomicExistingDeleteRecreateIsOneModification(t *testing.T) {
	c, p, original := nativeAtomicFixture(t)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	const final = "#!/bin/sh\necho replacement\n"
	n := nativeAtomicWrite(t, c, p, final)
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: p, Observed: true},
		nativeFIMObservation{Path: p, After: n, Observed: true},
	)
	nativeAssertAtomicModification(t, events, p, original, final)
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error { t.Fatalf("reconciliation duplicated replacement: %+v", e); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFIMAtomicExistingWriteDeleteWriteUsesFinalVersion(t *testing.T) {
	c, p, original := nativeAtomicFixture(t)
	intermediate := nativeAtomicWrite(t, c, p, "#!/bin/sh\necho intermediate\n")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	const final = "#!/bin/sh\necho final\n"
	n := nativeAtomicWrite(t, c, p, final)
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: p, After: intermediate, Observed: true},
		nativeFIMObservation{Path: p, Observed: true},
		nativeFIMObservation{Path: p, After: n, Observed: true},
	)
	nativeAssertAtomicModification(t, events, p, original, final)
}

func TestNativeFIMAtomicNewFileRemovalKeepsAddedAndDeleted(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "new.sh")
	const text = "#!/bin/sh\necho transient\n"
	n := nativeAtomicWrite(t, c, p, text)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: p, After: n, Observed: true},
		nativeFIMObservation{Path: p, Observed: true},
	)
	if len(events) != 2 {
		t.Fatalf("new lifecycle collapsed: %+v", events)
	}
	a, d := nativeFIMDetails(t, events[0]), nativeFIMDetails(t, events[1])
	if a["change"] != "added" || a["current_text"] != text || d["change"] != "deleted" || d["previous_text"] != text {
		t.Fatalf("new lifecycle evidence: %+v / %+v", a, d)
	}
}

func TestNativeFIMAtomicExistingWriteThenRemovalKeepsBothChanges(t *testing.T) {
	c, p, original := nativeAtomicFixture(t)
	const changed = "#!/bin/sh\necho before-removal\n"
	n := nativeAtomicWrite(t, c, p, changed)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: p, After: n, Observed: true},
		nativeFIMObservation{Path: p, Observed: true},
	)
	if len(events) != 2 {
		t.Fatalf("final removal swallowed real write/delete: %+v", events)
	}
	m, d := nativeFIMDetails(t, events[0]), nativeFIMDetails(t, events[1])
	if m["change"] != "modified" || m["previous_text"] != original || m["current_text"] != changed || d["change"] != "deleted" || d["previous_text"] != changed {
		t.Fatalf("write/delete evidence: %+v / %+v", m, d)
	}
}

func TestNativeFIMAtomicFinalRemovalDoesNotBecomeModification(t *testing.T) {
	c, p, original := nativeAtomicFixture(t)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	const temporary = "#!/bin/sh\necho recreated-then-removed\n"
	n := nativeAtomicWrite(t, c, p, temporary)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: p, Observed: true},
		nativeFIMObservation{Path: p, After: n, Observed: true},
		nativeFIMObservation{Path: p, Observed: true},
	)
	if len(events) != 3 {
		t.Fatalf("real remove/add/remove transitions collapsed: %+v", events)
	}
	for i, kind := range []string{"deleted", "added", "deleted"} {
		if nativeFIMDetails(t, events[i])["change"] != kind {
			t.Fatalf("unexpected transition %d: %+v", i, events[i])
		}
	}
	if nativeFIMDetails(t, events[0])["previous_text"] != original || nativeFIMDetails(t, events[2])["previous_text"] != temporary {
		t.Fatal("removal versions were lost")
	}
}

func TestNativeFIMAtomicDifferentPathsCoalesceIndependently(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.ReportChanges = true
	a, b := filepath.Join(root, "a.conf"), filepath.Join(root, "b.conf")
	nativeAtomicWrite(t, c, a, "old-a")
	nativeAtomicWrite(t, c, b, "old-b")
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.Remove(a)
	os.Remove(b)
	newA, newB := nativeAtomicWrite(t, c, a, "new-a"), nativeAtomicWrite(t, c, b, "new-b")
	events := nativeAtomicApply(t, c,
		nativeFIMObservation{Path: a, Observed: true},
		nativeFIMObservation{Path: b, Observed: true},
		nativeFIMObservation{Path: a, After: newA, Observed: true},
		nativeFIMObservation{Path: b, After: newB, Observed: true},
	)
	if len(events) != 2 {
		t.Fatalf("different files merged or duplicated: %+v", events)
	}
	got := map[string]security.Event{}
	for _, e := range events {
		p, _ := e.Data["path"].(string)
		got[p] = e
	}
	nativeAssertAtomicModification(t, []security.Event{got[a]}, a, "old-a", "new-a")
	nativeAssertAtomicModification(t, []security.Event{got[b]}, b, "old-b", "new-b")
	if events[0].ID == events[1].ID {
		t.Fatal("different paths share event identity")
	}
}

func TestNativeFIMAtomicQueueFailureReplaysOneStableModification(t *testing.T) {
	c, p, original := nativeAtomicFixture(t)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	const final = "#!/bin/sh\necho queued-final\n"
	n := nativeAtomicWrite(t, c, p, final)
	var reserved []security.Event
	accepted, err := nativeApplyObservations(c, []nativeFIMObservation{{Path: p, Observed: true}, {Path: p, After: n, Observed: true}}, func(e security.Event) error { reserved = append(reserved, e); return errors.New("outbox full") })
	if !accepted || err == nil || len(reserved) != 1 {
		t.Fatalf("durable coalesced reservation: %v %v %+v", accepted, err, reserved)
	}
	nativeAssertAtomicModification(t, reserved, p, original, final)
	var replay []security.Event
	if err := pollNativeFIM(context.Background(), NewSession(c), func(e security.Event) error { replay = append(replay, e); return nil }); err != nil {
		t.Fatal(err)
	}
	nativeAssertAtomicModification(t, replay, p, original, final)
	if replay[0].ID != reserved[0].ID {
		t.Fatal("coalesced retry changed stable identity")
	}
}
