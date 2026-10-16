package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/sealed"
	"anqu/internal/security"
)

func securityTestConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(filepath.Join(out, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	return Config{OutputDir: out, StateFile: filepath.Join(out, "state", "md5.json"), Server: []string{"127.0.0.1:55555"}, location: time.UTC, Security: &SecurityConfig{Config: security.Config{Enabled: true, MaxQueueEvents: 100}, NativeFIM: &NativeFIMConfig{Enabled: true, PollIntervalSeconds: 30, MaxDiffBytes: 8192}}}
}

func TestSecurityQueuePersistsAndTracksEveryDestinationACK(t *testing.T) {
	c := securityTestConfig(t)
	c.Server = []string{"first:55555", "second:55555"}
	q, err := openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	event := security.Event{ID: "stable-id", Type: "security_event", Time: time.Now(), Data: map[string]any{"source": "auditd", "kind": "process_exec", "command": "PRIVATE_COMMAND"}}
	if err := q.enqueue(c, event); err != nil {
		t.Fatal(err)
	}
	if err := q.enqueue(c, event); err != nil {
		t.Fatal(err)
	}
	if len(q.files) != 1 {
		t.Fatal("duplicate queue record")
	}
	for _, file := range q.files {
		b, err := os.ReadFile(filepath.Join(q.dir, file))
		if err != nil || !sealed.IsState(b) || bytes.Contains(b, []byte("PRIVATE_COMMAND")) {
			t.Fatal("outbox is not encrypted")
		}
	}
	var attempts []string
	_, err = q.drain(context.Background(), c, func(_ context.Context, _ Config, target string, events []historyEvent) error {
		attempts = append(attempts, target)
		if events[0].ID != "stable-id" {
			t.Fatal("identity changed")
		}
		if target == "second:55555" {
			return errors.New("offline")
		}
		return nil
	})
	if err == nil || len(attempts) != 2 {
		t.Fatalf("all destinations not attempted: %v %v", attempts, err)
	}
	q, err = openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	attempts = nil
	more, err := q.drain(context.Background(), c, func(_ context.Context, _ Config, target string, _ []historyEvent) error {
		attempts = append(attempts, target)
		return nil
	})
	if err != nil || more || len(attempts) != 1 || attempts[0] != "second:55555" {
		t.Fatalf("ACK progress not retained: %v %v %v", attempts, more, err)
	}
}

func TestSecurityQueueBackpressureDoesNotDeleteRecords(t *testing.T) {
	c := securityTestConfig(t)
	q, err := openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	q.limit = 1
	e := security.Event{ID: "one", Type: "security_event", Time: time.Now(), Data: map[string]any{"message": "one"}}
	if err := q.enqueue(c, e); err != nil {
		t.Fatal(err)
	}
	e.ID = "two"
	if err := q.enqueue(c, e); err == nil {
		t.Fatal("full outbox accepted event")
	}
	if len(q.files) != 1 {
		t.Fatal("pending record lost")
	}
	e.Data["message"] = strings.Repeat("x", 50001)
	if err := q.enqueue(c, e); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestComponentStatusRemainsDeliverableWithLargePolicyOutput(t *testing.T) {
	c := securityTestConfig(t)
	q, err := openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	// Control characters amplify during JSON encoding; a raw byte limit alone
	// cannot guarantee that the UDP envelope stays within its budget.
	checks := make([]any, 80)
	for i := range checks {
		checks[i] = map[string]any{"setting": "sudo.grant.ops", "expected": strings.Repeat("\x00", 20000), "actual": strings.Repeat("\x00", 32768), "message": strings.Repeat("检查", 1000), "compliant": false}
	}
	components := []map[string]any{{"name": "policies", "state": "drift", "enabled": true, "message": strings.Repeat("\x00", 32768), "checks": checks}}
	data := map[string]any{"inventory": securityInventory(), "queue": q.stats()}
	boundSecurityStatus(data, components)
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > 48000 {
		t.Fatalf("unbounded status: %d bytes, %v", len(raw), err)
	}
	if components[0]["state"] != "drift" || components[0]["omitted_checks"] != 80 || data["details_truncated"] != true {
		t.Fatalf("health or omission indicators lost: %+v", data)
	}
	if err := q.enqueue(c, security.Event{Type: "component_status", Data: data}); err != nil {
		t.Fatal(err)
	}
	brief := []map[string]any{{"name": "policies", "checks": []any{map[string]any{"setting": "sysctl.x", "actual": "1", "expected": "1", "compliant": true}}}}
	data = map[string]any{}
	boundSecurityStatus(data, brief)
	if data["details_truncated"] == true || len(brief[0]["checks"].([]any)) != 1 {
		t.Fatal("ordinary check details unnecessarily removed")
	}
}

func TestSecurityQueueOfflineTargetDoesNotStarveHealthyDestination(t *testing.T) {
	c := securityTestConfig(t)
	c.Server = []string{"offline:55555", "healthy:55555"}
	q, err := openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 75; i++ {
		if err := q.enqueue(c, security.Event{ID: fmt.Sprint(i), Type: "security_event", Time: time.Now(), Data: map[string]any{"source": "test"}}); err != nil {
			t.Fatal(err)
		}
	}
	received := map[string]bool{}
	for turn := 0; turn < 3; turn++ {
		_, _ = q.drain(context.Background(), c, func(_ context.Context, _ Config, target string, events []historyEvent) error {
			if target == "offline:55555" {
				return errors.New("offline")
			}
			received[events[0].ID] = true
			return nil
		})
	}
	if len(received) != 75 {
		t.Fatalf("offline target blocked healthy receiver: %d/75", len(received))
	}
	if len(q.files) != 75 {
		t.Fatal("unacknowledged offline copies were discarded")
	}
}

func TestNativeFIMRetainsBaselineAcrossRestartAndRetries(t *testing.T) {
	c := securityTestConfig(t)
	root := filepath.Join(t.TempDir(), "watch")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "service.conf")
	if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	c.Security.NativeFIM.Paths = []string{root}
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("first baseline has changes: %+v", events)
	}
	if err := os.WriteFile(p, []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	c = NewSession(c)
	var firstID string
	err := pollNativeFIM(context.Background(), c, func(e security.Event) error { firstID = e.ID; return errors.New("outbox full") })
	if err == nil || firstID == "" {
		t.Fatal("emit failure ignored")
	}
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != firstID || events[0].Data["path"] != p {
		t.Fatalf("change lost or unstable identity: %+v", events)
	}
	events = nil
	if err := pollNativeFIM(context.Background(), NewSession(c), emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatal("unchanged data repeated after restart")
	}
	info, _ := os.Stat(p)
	at := info.ModTime().Add(5 * time.Second)
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatal("attribute-only change missed")
	}
}

func TestNativeFIMSensitiveTextNeverStoredOrReported(t *testing.T) {
	c := securityTestConfig(t)
	c.Security.NativeFIM.ReportChanges = true
	root := t.TempDir()
	p := filepath.Join(root, "shadow")
	os.WriteFile(p, []byte("SENSITIVE_CONTENT"), 0600)
	c.Security.NativeFIM.Paths = []string{p}
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var state nativeFIMState
	if err := readState(filepath.Join(securityDataDir(c), "native-fim.state"), "security-fim", &state); err != nil {
		t.Fatal(err)
	}
	if state.Files[p].Text != "" {
		t.Fatal("sensitive text stored")
	}
	os.WriteFile(p, []byte("CHANGED_SECRET"), 0600)
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error {
		details := e.Data["details"].(map[string]any)
		if _, exists := details["current_text"]; exists {
			t.Fatal("sensitive diff reported")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFIMPartiallyQueuedSnapshotDoesNotLoseRestoration(t *testing.T) {
	c := securityTestConfig(t)
	root := t.TempDir()
	a, b := filepath.Join(root, "a.conf"), filepath.Join(root, "b.conf")
	os.WriteFile(a, []byte("A"), 0600)
	os.WriteFile(b, []byte("A"), 0600)
	c.Security.NativeFIM.Paths = []string{root}
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(a, []byte("B"), 0600)
	os.WriteFile(b, []byte("B"), 0600)
	var first []security.Event
	err := pollNativeFIM(context.Background(), c, func(e security.Event) error {
		if len(first) == 1 {
			return errors.New("full")
		}
		first = append(first, e)
		return nil
	})
	if err == nil || len(first) != 1 {
		t.Fatal("test did not exercise partial publication")
	}
	os.WriteFile(a, []byte("A"), 0600)
	var replay []security.Event
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error { replay = append(replay, e); return nil }); err != nil {
		t.Fatal(err)
	}
	foundRestoration := false
	for _, e := range replay {
		if e.ID == first[0].ID {
			t.Fatal("event identity was reused")
		}
		if e.Data["path"] == a {
			foundRestoration = true
		}
	}
	if !foundRestoration {
		t.Fatalf("restoration lost after partial snapshot: %+v", replay)
	}
}

func TestSecurityYAMLStrictValidationAndLegacyCompatibility(t *testing.T) {
	base := t.TempDir()
	prefix := "output_dir: output\nlogin: {enabled: false}\nserver: ['127.0.0.1:55555']\nsetup: {logs: logs/a.log, prom: metrics/a.prom}\n"
	valid := prefix + "security:\n  enabled: true\n  auditd: {enabled: true}\n  native_fim: {enabled: true, paths: [watched]}\n"
	c, err := ParseConfig([]byte(valid), base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Security.NativeFIM.PollIntervalSeconds != 30 || !filepath.IsAbs(c.Security.NativeFIM.Paths[0]) {
		t.Fatal("security normalization missing")
	}
	if _, err := ParseConfig([]byte(prefix+"security: {enabled: true, misspelled: true}\n"), base); err == nil {
		t.Fatal("unknown security field accepted")
	}
	if _, err := ParseConfig([]byte("output_dir: output\nlogin: {enabled: false}\nserver: []\nsecurity: {enabled: true}\n"), base); err == nil {
		t.Fatal("security without a report destination accepted")
	}
	if _, err := ParseConfig([]byte(prefix), base); err != nil {
		t.Fatalf("old config broken: %v", err)
	}
}

func TestPublishedSecurityExampleValidatesForLinux(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "security.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEmbeddedYAML(data, "linux"); err != nil {
		t.Fatalf("published security example is invalid: %v", err)
	}
}
