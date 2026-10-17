package audit

import (
	"errors"
	"testing"
	"time"

	"anqu/internal/security"
)

func reportingStatus(at time.Time, state string, pending int) security.Event {
	return security.Event{Type: "component_status", Time: at, Data: map[string]any{
		"components": []map[string]any{{"name": "auditd", "state": "running", "running": true}, {"name": "native_fim", "state": state, "enabled": true}},
		"queue":      map[string]any{"pending": pending}, "inventory": map[string]any{"cpu_count": 2},
	}}
}

func TestComponentStatusOnlySendsChangesAndLowFrequencySnapshots(t *testing.T) {
	var reporter componentStatusReporter
	var delivered []security.Event
	persist := func(event security.Event) error { delivered = append(delivered, event); return nil }
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		event := reportingStatus(start.Add(time.Duration(i)*30*time.Second), "running", i)
		components := event.Data["components"].([]map[string]any)
		components[0]["applied_at"] = event.Time
		if err := reporter.emit(event, persist); err != nil {
			t.Fatal(err)
		}
	}
	if len(delivered) != 1 {
		t.Fatalf("stable health/queue/time changes generated %d reports, want 1", len(delivered))
	}
	if err := reporter.emit(reportingStatus(start.Add(5*time.Minute), "running", 10), persist); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 2 || delivered[1].Data["snapshot_only"] != true || delivered[1].Data["status_reporting"] != "changes_only" || delivered[1].Data["snapshot_interval_seconds"] != 300 {
		t.Fatalf("latest-status refresh was not marked as a low-frequency snapshot: %+v", delivered)
	}
	for _, tc := range []struct {
		seconds int
		state   string
	}{{310, "error"}, {320, "error"}, {330, "running"}} {
		if err := reporter.emit(reportingStatus(start.Add(time.Duration(tc.seconds)*time.Second), tc.state, 0), persist); err != nil {
			t.Fatal(err)
		}
	}
	if len(delivered) != 4 || delivered[2].Data["snapshot_only"] == true || delivered[3].Data["snapshot_only"] == true {
		t.Fatalf("native component failure/recovery was lost or repeated: %+v", delivered)
	}
}

func TestComponentStatusFailedEnqueueIsRetriedAndEventsAreUnaffected(t *testing.T) {
	var reporter componentStatusReporter
	at := time.Now().UTC()
	want := errors.New("outbox full")
	if err := reporter.emit(reportingStatus(at, "error", 0), func(security.Event) error { return want }); !errors.Is(err, want) {
		t.Fatalf("enqueue error hidden: %v", err)
	}
	var delivered []security.Event
	persist := func(event security.Event) error { delivered = append(delivered, event); return nil }
	if err := reporter.emit(reportingStatus(at.Add(time.Second), "error", 0), persist); err != nil || len(delivered) != 1 {
		t.Fatalf("failed status was consumed: %+v %v", delivered, err)
	}
	event := security.Event{Type: "security_event", Time: at, Data: map[string]any{"source": "ssh_auth", "severity": "warning"}}
	for range 2 {
		if err := reporter.emit(event, persist); err != nil {
			t.Fatal(err)
		}
	}
	if len(delivered) != 3 {
		t.Fatal("component status suppression affected security events")
	}
}
