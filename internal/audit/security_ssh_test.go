package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"anqu/internal/security"
)

func failureJournalLine(cursor, message string, at time.Time) string {
	b, _ := json.Marshal(journalLoginEntry{Cursor: cursor, Timestamp: fmt.Sprint(at.UnixMicro()), Message: message})
	return string(b) + "\n"
}

func TestSSHFailureAuditThresholdAndDurableCursor(t *testing.T) {
	now := time.Now()
	cfg := SecuritySSHAuthConfig{AlertThreshold: 2, WindowSeconds: 300}
	state := sshFailureState{Version: 1, Sources: map[string]sshFailureWindow{}}
	var input strings.Builder
	for i := 1; i <= 3; i++ {
		input.WriteString(failureJournalLine(fmt.Sprint(i), "Failed password for invalid user administrator from 192.0.2.10 port 4040 ssh2", now.Add(time.Duration(i)*time.Second)))
	}
	var events []security.Event
	more, err := parseSSHFailurePage(strings.NewReader(input.String()), cfg, &state, func(event security.Event) error { events = append(events, event); return nil })
	if err != nil || more || state.Cursor != "3" {
		t.Fatalf("bad cursor: %+v %v", state, err)
	}
	if len(events) != 4 || events[2].Data["kind"] != "ssh_bruteforce" || events[2].Data["severity"] != "warning" {
		t.Fatalf("threshold not honored: %+v", events)
	}
	if events[0].Data["user"] != "administrator" {
		t.Fatal("invalid user parse failed")
	}
	state = sshFailureState{Version: 1}
	_, err = parseSSHFailurePage(strings.NewReader(input.String()), cfg, &state, func(event security.Event) error { return errors.New("full") })
	if err == nil || state.Cursor != "" {
		t.Fatal("failed publication advanced source")
	}
}
