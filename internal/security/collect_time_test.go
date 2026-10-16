package security

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackfilledSourceTimeSurvivesCollectorRetry(t *testing.T) {
	cases := []struct {
		name, path, content string
		config              Config
		want                time.Time
	}{
		{
			name: "auditd",
			path: "/var/log/audit/audit.log",
			content: "type=SYSCALL msg=audit(1700000000.123456789:42): auid=1000 key=\"anquan_exec\"\n" +
				"type=EOE msg=audit(1700000000.123456789:42):\n",
			config: Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}},
			want:   time.Unix(1700000000, 123456789).UTC(),
		},
		{
			name:    "tetragon",
			path:    "/var/log/tetragon/tetragon.log",
			content: "{\"time\":\"2020-01-02T03:04:05.123456789+08:00\",\"process_exec\":{\"process\":{\"pid\":42}}}\n",
			config:  Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}},
			want:    time.Date(2020, 1, 1, 19, 4, 5, 123456789, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testManager(t, tc.config)
			put(t, m, tc.path, []byte(tc.content))
			var first Event
			err := m.Poll(context.Background(), func(e Event) error {
				first = e
				return errors.New("outbox full")
			})
			if err == nil || !first.Time.Equal(tc.want) {
				t.Fatalf("backfill did not preserve source time: event=%+v err=%v", first, err)
			}
			// Recreate the collector before retrying so an uncommitted cursor is
			// replayed exactly as it would be after a service restart.
			restarted := NewManager(m.Config, m.OutputDir)
			restarted.RootDir, restarted.Runner = m.RootDir, m.Runner
			var retried []Event
			if err := restarted.Poll(context.Background(), func(e Event) error {
				retried = append(retried, e)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(retried) != 1 || retried[0].ID != first.ID || !retried[0].Time.Equal(tc.want) || retried[0].Time.Location() != time.UTC {
				t.Fatalf("restart changed source time or identity: first=%+v retried=%+v", first, retried)
			}
		})
	}
}

func TestInvalidSourceTimeFallsBackToCollectionTime(t *testing.T) {
	cases := []struct {
		name, path, content string
		config              Config
	}{
		{
			name: "auditd-overflow",
			path: "/var/log/audit/audit.log",
			content: "type=SYSCALL msg=audit(9999999999999999999999.001:42): key=\"anquan_exec\"\n" +
				"type=EOE msg=audit(9999999999999999999999.001:42):\n",
			config: Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}},
		},
		{
			name: "auditd-year-outside-json-range",
			path: "/var/log/audit/audit.log",
			content: "type=SYSCALL msg=audit(253402300800:42): key=\"anquan_exec\"\n" +
				"type=EOE msg=audit(253402300800:42):\n",
			config: Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}},
		},
		{name: "tetragon-invalid", path: "/var/log/tetragon/tetragon.log", content: "{\"time\":\"invalid\",\"process_exit\":{}}\n", config: Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}}},
		{name: "tetragon-missing", path: "/var/log/tetragon/tetragon.log", content: "{\"process_exit\":{}}\n", config: Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testManager(t, tc.config)
			put(t, m, tc.path, []byte(tc.content))
			before := time.Now().UTC()
			var events []Event
			if err := m.Poll(context.Background(), func(e Event) error { events = append(events, e); return nil }); err != nil {
				t.Fatal(err)
			}
			after := time.Now().UTC()
			if len(events) != 1 || events[0].Time.Before(before) || events[0].Time.After(after) {
				t.Fatalf("invalid source time did not fall back to collection time: %+v", events)
			}
		})
	}
}
