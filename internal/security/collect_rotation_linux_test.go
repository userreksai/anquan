//go:build linux

package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rotationTetragonPath = "/var/log/tetragon/tetragon.log"

func rotationRecord(pid int) string {
	return fmt.Sprintf("{\"process_exec\":{\"process\":{\"pid\":%d}}}\n", pid)
}

func appendRotationLog(t *testing.T, m *Manager, path, content string) {
	t.Helper()
	f, err := os.OpenFile(m.path(path), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func renameRotationLog(t *testing.T, m *Manager, path, name string) string {
	t.Helper()
	rotated := filepath.Join(filepath.Dir(m.path(path)), name)
	if err := os.Rename(m.path(path), rotated); err != nil {
		t.Fatal(err)
	}
	return rotated
}

func pollRotationEvents(t *testing.T, m *Manager) []Event {
	t.Helper()
	var events []Event
	if err := m.Poll(context.Background(), func(e Event) error {
		events = append(events, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return events
}

func assertRotationPIDs(t *testing.T, events []Event, want ...int) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("expected %d process events, got %d: %+v", len(want), len(events), events)
	}
	for i, event := range events {
		if event.Data["kind"] != "process_exec" {
			t.Fatalf("event %d is not a process event (unexpected gap): %+v", i, event)
		}
		raw := event.Data["event"].(map[string]any)
		process := raw["process_exec"].(map[string]any)["process"].(map[string]any)
		if got := int(process["pid"].(float64)); got != want[i] {
			t.Fatalf("event %d: pid %d, want %d", i, got, want[i])
		}
	}
}

func rotationStateBytes(t *testing.T, m *Manager) []byte {
	t.Helper()
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func restartedRotationManager(m *Manager) *Manager {
	restarted := NewManager(m.Config, m.OutputDir)
	restarted.RootDir, restarted.Runner = m.RootDir, m.Runner
	return restarted
}

func TestTetragonTimestampRotationDrainsUnreadTailBeforeCurrent(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	put(t, m, rotationTetragonPath, []byte(rotationRecord(1)))
	assertRotationPIDs(t, pollRotationEvents(t, m), 1)
	appendRotationLog(t, m, rotationTetragonPath, rotationRecord(2)+rotationRecord(3))
	renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")
	put(t, m, rotationTetragonPath, []byte(rotationRecord(4)))

	assertRotationPIDs(t, pollRotationEvents(t, m), 2, 3, 4)
	assertRotationPIDs(t, pollRotationEvents(t, m))
}

func TestTetragonTimestampRotationAtEOFDoesNotReportGap(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	put(t, m, rotationTetragonPath, []byte(rotationRecord(1)))
	assertRotationPIDs(t, pollRotationEvents(t, m), 1)
	renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")
	put(t, m, rotationTetragonPath, []byte(rotationRecord(2)))

	assertRotationPIDs(t, pollRotationEvents(t, m), 2)
	assertRotationPIDs(t, pollRotationEvents(t, m))
}

func TestNumericLogRotationsRemainReadable(t *testing.T) {
	for _, tc := range []struct{ source, path string }{
		{source: "auditd", path: "/var/log/audit/audit.log"},
		{source: "sudo", path: "/var/log/anquan-sudo.log"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			m, _ := testManager(t, Config{Enabled: true})
			s := collectorState{Cursors: map[string]logCursor{}}
			var events []Event
			emit := func(e Event) error { events = append(events, e); return nil }
			collect := func() {
				t.Helper()
				if err := m.collectLog(context.Background(), &s, tc.path, tc.source, func(line, key string) error {
					return emit(newEvent(tc.source, "line", "info", line, key, nil))
				}, emit); err != nil {
					t.Fatal(err)
				}
			}
			put(t, m, tc.path, []byte("already collected\n"))
			collect()
			events = nil
			appendRotationLog(t, m, tc.path, "old tail\n")
			renameRotationLog(t, m, tc.path, filepath.Base(tc.path)+".1")
			put(t, m, tc.path, []byte("new log\n"))

			collect()
			if len(events) != 2 || events[0].Message != "old tail" || events[1].Message != "new log" {
				t.Fatalf("numeric rotation skipped or reordered records: %+v", events)
			}
			events = nil
			collect()
			if len(events) != 0 {
				t.Fatalf("numeric rotation replayed committed records: %+v", events)
			}
		})
	}
}

func TestTetragonRotationDrainsAcrossBatchBoundary(t *testing.T) {
	for _, unread := range []int{500, 501} {
		t.Run(fmt.Sprintf("unread_%d", unread), func(t *testing.T) {
			m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
			put(t, m, rotationTetragonPath, []byte(rotationRecord(0)))
			assertRotationPIDs(t, pollRotationEvents(t, m), 0)
			before, err := m.loadCollectorState()
			if err != nil {
				t.Fatal(err)
			}
			var tail strings.Builder
			for pid := 1; pid <= unread; pid++ {
				tail.WriteString(rotationRecord(pid))
			}
			appendRotationLog(t, m, rotationTetragonPath, tail.String())
			renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")
			put(t, m, rotationTetragonPath, []byte(rotationRecord(10000)))

			firstPIDs := make([]int, 500)
			for i := range firstPIDs {
				firstPIDs[i] = i + 1
			}
			assertRotationPIDs(t, pollRotationEvents(t, m), firstPIDs...)
			after, err := m.loadCollectorState()
			if err != nil {
				t.Fatal(err)
			}
			if after.Cursors[rotationTetragonPath].Identity != before.Cursors[rotationTetragonPath].Identity {
				t.Fatal("collector switched to current log before confirming the old batch reached EOF")
			}
			// Restart between batches to verify that the rotated inode and offset
			// survive a checkpoint, including exactly 500 remaining records.
			restarted := restartedRotationManager(m)
			var remaining []int
			for pid := 501; pid <= unread; pid++ {
				remaining = append(remaining, pid)
			}
			remaining = append(remaining, 10000)
			assertRotationPIDs(t, pollRotationEvents(t, restarted), remaining...)
			assertRotationPIDs(t, pollRotationEvents(t, restarted))
		})
	}
}

func TestTetragonRotationEmitFailurePreservesCheckpointAndStableIDs(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	put(t, m, rotationTetragonPath, []byte(rotationRecord(0)))
	assertRotationPIDs(t, pollRotationEvents(t, m), 0)
	checkpoint := rotationStateBytes(t, m)
	appendRotationLog(t, m, rotationTetragonPath, rotationRecord(1)+rotationRecord(2))
	renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")
	put(t, m, rotationTetragonPath, []byte(rotationRecord(3)))
	queueErr := errors.New("rotation test queue full")
	var attempted []Event
	err := m.Poll(context.Background(), func(e Event) error {
		attempted = append(attempted, e)
		if len(attempted) == 2 {
			return queueErr
		}
		return nil
	})
	if !errors.Is(err, queueErr) {
		t.Fatalf("expected queue failure, got %v", err)
	}
	assertRotationPIDs(t, attempted, 1, 2)
	if !bytes.Equal(checkpoint, rotationStateBytes(t, m)) {
		t.Fatal("failed rotated batch advanced the persisted checkpoint")
	}

	restarted := restartedRotationManager(m)
	retried := pollRotationEvents(t, restarted)
	assertRotationPIDs(t, retried, 1, 2, 3)
	for i := range attempted {
		if retried[i].ID != attempted[i].ID {
			t.Fatalf("event %d changed ID after restart: %s -> %s", i, attempted[i].ID, retried[i].ID)
		}
	}
	assertRotationPIDs(t, pollRotationEvents(t, restarted))
}

func TestTetragonMissingRotatedSourceReportsGapOnceAndContinues(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	initial := rotationRecord(0)
	put(t, m, rotationTetragonPath, []byte(initial))
	assertRotationPIDs(t, pollRotationEvents(t, m), 0)
	appendRotationLog(t, m, rotationTetragonPath, rotationRecord(1))
	rotated := renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")
	// Create the new inode before unlinking the old one, preventing inode reuse
	// from turning this fixture into a same-inode truncation case.
	put(t, m, rotationTetragonPath, []byte(rotationRecord(2)))
	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}

	events := pollRotationEvents(t, m)
	if len(events) != 2 || events[0].Data["kind"] != "collection_gap" || events[0].Data["offset"] != int64(len(initial)) {
		t.Fatalf("missing source did not report its saved offset: %+v", events)
	}
	assertRotationPIDs(t, events[1:], 2)
	assertRotationPIDs(t, pollRotationEvents(t, m))
}

func TestTetragonRotationMissingCurrentPreservesCursorUntilRecreated(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	put(t, m, rotationTetragonPath, []byte(rotationRecord(0)))
	assertRotationPIDs(t, pollRotationEvents(t, m), 0)
	before, err := m.loadCollectorState()
	if err != nil {
		t.Fatal(err)
	}
	appendRotationLog(t, m, rotationTetragonPath, rotationRecord(1))
	renameRotationLog(t, m, rotationTetragonPath, "tetragon-2026-10-18T22-27-08.835.log")

	assertRotationPIDs(t, pollRotationEvents(t, m))
	after, err := m.loadCollectorState()
	if err != nil {
		t.Fatal(err)
	}
	if after.Cursors[rotationTetragonPath] != before.Cursors[rotationTetragonPath] {
		t.Fatalf("temporary absence changed cursor: before=%+v after=%+v", before.Cursors[rotationTetragonPath], after.Cursors[rotationTetragonPath])
	}
	put(t, m, rotationTetragonPath, []byte(rotationRecord(2)))
	restarted := restartedRotationManager(m)
	assertRotationPIDs(t, pollRotationEvents(t, restarted), 1, 2)
	assertRotationPIDs(t, pollRotationEvents(t, restarted))
}
