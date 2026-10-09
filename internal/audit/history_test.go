package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/sealed"
)

func historyTestConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	c, err := ParseConfig([]byte(`output_dir: output
login: {enabled: false}
server: ["127.0.0.1:55555"]
setup: {logs: logs/agent.log, prom: metrics/agent.prom, interval_seconds: 300}
history: {enabled: true, path: history.log, timezone: UTC, poll_interval_ms: 100, max_records: 2}
`), base)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func historyLine(command string) string {
	return "[2026-10-09 02:42:50] [root] [/dev/pts/1] [" + command + "]\n"
}

func TestHistoryParserPreservesBracketsQuotesAndTimestamp(t *testing.T) {
	for _, command := range []string{"alias ll='ls -alF'", "[ -f ~/.bash_aliases ]", `printf '%s' '[a] [b]'`, "  echo 中文  ", "history"} {
		r, err := parseHistoryLine(historyLine(command), "/var/log/history.log", "id", 0, time.FixedZone("test", 7*3600))
		if err != nil || r.Command != command || r.User != "root" || r.Terminal != "/dev/pts/1" || r.CommandTime.Format(time.RFC3339) != "2026-10-09T02:42:50+07:00" {
			t.Fatalf("record=%+v err=%v", r, err)
		}
	}
	for _, line := range []string{"broken", "[2026-99-99 02:42:50] [root] [-] [ls]\n", historyLine(""), historyLine(string([]byte{0xff}))} {
		if _, err := parseHistoryLine(line, "history.log", "id", 0, time.UTC); err == nil {
			t.Fatalf("invalid line accepted: %q", line)
		}
	}
}

func TestHistoryBackfillAppendPartialTailAndRestart(t *testing.T) {
	c := historyTestConfig(t)
	line := historyLine("history")
	partial := strings.TrimSuffix(historyLine("[ -f ~/.bash_aliases ]"), "\n")
	put(t, c.History.Path, line+line+line+partial)
	var events []historyEvent
	send := func(_ Config, batch []historyEvent) error { events = append(events, batch...); return nil }
	for i := 0; i < 4; i++ {
		if _, err := pollHistory(c, nil, send); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 3 || events[0].ID == events[1].ID {
		t.Fatalf("backfill/dedup lost distinct occurrences: %+v", events)
	}
	statePath := c.StateFile + ".commands"
	before := read(t, statePath)
	if !sealed.IsState([]byte(before)) || strings.Contains(before, "history") {
		t.Fatal("command cursor/outbox not encrypted")
	}
	if _, err := pollHistory(NewSession(c), nil, send); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || read(t, statePath) != before {
		t.Fatal("restart replayed data or rewrote idle cursor")
	}
	put(t, c.History.Path, line+line+line+partial+"\n"+historyLine("tail -f /var/log/history.log"))
	if _, err := pollHistory(NewSession(c), nil, send); err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("partial/append lost: %d", len(events))
	}
	var record CommandRecord
	if err := json.Unmarshal(events[3].Data, &record); err != nil || record.Command != "[ -f ~/.bash_aliases ]" {
		t.Fatalf("nested bracket command: %+v %v", record, err)
	}
}

func TestHistoryDurablePendingRetryAndMalformedRecord(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("echo PRIVATE_COMMAND")+"invalid record\n")
	var first []historyEvent
	failed := func(_ Config, batch []historyEvent) error {
		first = append(first, batch...)
		return errors.New("master down")
	}
	if _, err := pollHistory(c, nil, failed); err == nil {
		t.Fatal("delivery failure ignored")
	}
	var state historyState
	if err := readState(c.StateFile+".commands", "history", &state); err != nil || len(state.Pending) != 2 || state.Pending[1].Type != "alert" {
		t.Fatalf("pending not durable: %+v %v", state, err)
	}
	if strings.Contains(read(t, c.StateFile+".commands"), "PRIVATE_COMMAND") {
		t.Fatal("plaintext command in pending state")
	}
	// Source may be unavailable while an already durable batch is retried.
	if err := os.Remove(c.History.Path); err != nil {
		t.Fatal(err)
	}
	var retried []historyEvent
	if _, err := pollHistory(NewSession(c), nil, func(_ Config, batch []historyEvent) error { retried = append(retried, batch...); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(retried) != 2 || retried[0].ID != first[0].ID || retried[1].ID != first[1].ID {
		t.Fatal("retry changed identity or lost queued command")
	}
	state = historyState{}
	if err := readState(c.StateFile+".commands", "history", &state); err != nil || len(state.Pending) != 0 {
		t.Fatal("ACKed queue not cleared")
	}
}

func TestHistoryDetectsTruncationAndKeepsCursor(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	send := func(Config, []historyEvent) error { return nil }
	if _, err := pollHistory(c, nil, send); err != nil {
		t.Fatal(err)
	}
	before := read(t, c.StateFile+".commands")
	put(t, c.History.Path, historyLine("new command")) // Same size, changed prefix/anchor.
	if _, err := pollHistory(c, nil, send); err == nil || read(t, c.StateFile+".commands") != before {
		t.Fatal("rewritten history silently advanced/reset")
	}
}

func TestHistorySendRequiresMatchingACKAndCancellation(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := historyTestConfig(t)
	c.Server = []string{conn.LocalAddr().String()}
	event := historyEvent{ID: "offset-id", Type: "command_history", Time: time.Now(), Data: json.RawMessage(`{"command":"test"}`)}
	done := make(chan error, 1)
	go func() { done <- sendHistoryEvents(c, []historyEvent{event}) }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 60000)
	n, remote, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	var envelope udpEnvelope
	if err := json.Unmarshal(buf[:n], &envelope); err != nil || !envelope.AckRequested {
		t.Fatal("ACK not requested")
	}
	wrong := []byte(`{"version":1,"type":"ack","event_id":"wrong"}`)
	_, _ = conn.WriteToUDP(wrong, remote)
	select {
	case err := <-done:
		t.Fatalf("wrong ACK accepted: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	ack, _ := json.Marshal(map[string]any{"version": 1, "type": "ack", "event_id": envelope.EventID})
	_, _ = conn.WriteToUDP(ack, remote)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- sendHistoryEventsContext(ctx, c, []historyEvent{event}) }()
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unacknowledged command accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked waiting for ACK")
	}
}

func TestHistoryRunsWhileFileScanIsBlocked(t *testing.T) {
	c := historyTestConfig(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c.Server = []string{conn.LocalAddr().String()}
	put(t, c.History.Path, historyLine("echo independent"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, c, nil, "test", func(Config, io.Writer) (Report, OutputPaths, error) {
			close(scanStarted)
			<-ctx.Done()
			return Report{}, OutputPaths{}, nil
		})
	}()
	<-scanStarted
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		buf := make([]byte, 60000)
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatal("command blocked by scan:", err)
		}
		var e udpEnvelope
		if err := json.Unmarshal(buf[:n], &e); err != nil {
			t.Fatal(err)
		}
		if e.Type != "command_history" {
			continue
		}
		ack, _ := json.Marshal(map[string]any{"version": 1, "type": "ack", "event_id": e.EventID})
		_, _ = conn.WriteToUDP(ack, remote)
		break
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestHistoryConfigurationAndNoPlaintextOutboxOnFailure(t *testing.T) {
	c := historyTestConfig(t)
	if c.History.location != time.UTC {
		t.Fatal("history timezone ignored")
	}
	for _, field := range []string{"poll_interval_ms: 1", "max_records: 0", "timezone: no_such_zone"} {
		// max_records=0 is intentionally the documented default.
		_, err := ParseConfig([]byte("output_dir: output\nlogin: {enabled: false}\nserver: ['127.0.0.1:55555']\nsetup: {logs: logs/a.log, prom: metrics/a.prom}\nhistory: {enabled: true, path: history.log, "+field+"}\n"), t.TempDir())
		if (err == nil) != (field == "max_records: 0") {
			t.Fatalf("field %s: %v", field, err)
		}
	}
	put(t, c.History.Path, historyLine("ls"))
	var log bytes.Buffer
	_, err := pollHistory(c, &log, func(Config, []historyEvent) error { return errors.New("retry") })
	if err == nil || !strings.Contains(log.String(), "command_history") {
		t.Fatal("command not logged before delivery")
	}
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(c.StateFile), ".anqu-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary state files remain")
	}
}
