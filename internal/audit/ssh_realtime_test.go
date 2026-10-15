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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sshRealtimeConfig(t *testing.T) Config {
	t.Helper()
	c := monitoringTestConfig(t)
	c.Setup.IntervalSeconds = 300
	c.Login.PollIntervalMS = 100
	return c
}

func appendSSHJSONL(t *testing.T, path, records string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(f, records)
	closeErr := f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func sshRealtimePackets(t *testing.T, listener net.PacketConn, timeout time.Duration) []udpEnvelope {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var packets []udpEnvelope
	for {
		buf := make([]byte, 65536)
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				return packets
			}
			t.Fatal(err)
		}
		var packet udpEnvelope
		if err := json.Unmarshal(buf[:n], &packet); err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}
}

func sshRealtimeRecords(t *testing.T, packets []udpEnvelope) []LoginRecord {
	t.Helper()
	var records []LoginRecord
	for _, packet := range packets {
		if packet.Type != "ssh_login" {
			continue
		}
		var record LoginRecord
		if err := json.Unmarshal(packet.Data, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestSSHRealtimeArrivesDuringBlockedScanWithoutIncreasingScanFrequency(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	var scans atomic.Int32
	var finished bool
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(1500 * time.Millisecond):
				t.Error("SSH worker did not stop after cancellation")
			}
		}
	})
	go func() {
		done <- serve(ctx, c, nil, "ssh-realtime-test", func(Config, io.Writer) (Report, OutputPaths, error) {
			if scans.Add(1) == 1 {
				close(started)
			}
			<-ctx.Done()
			return Report{Success: true}, OutputPaths{}, nil
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first scan did not start")
	}
	at := time.Now().UTC().Truncate(time.Second)
	appendSSHJSONL(t, c.Login.Path, loginJSON("root", "session-one", at)+loginJSON("root", "session-two", at))
	if err := listener.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	envelopes := map[string]bool{}
	for len(seen) < 2 {
		buf := make([]byte, 65536)
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			t.Fatalf("SSH notification was delayed by the blocked scan: %v", err)
		}
		var packet udpEnvelope
		if err := json.Unmarshal(buf[:n], &packet); err != nil {
			t.Fatal(err)
		}
		if packet.Type == "heartbeat" {
			continue
		}
		if packet.Type != "ssh_login" {
			t.Fatalf("login worker emitted %s while the full scan was blocked", packet.Type)
		}
		var record LoginRecord
		if err := json.Unmarshal(packet.Data, &record); err != nil {
			t.Fatal(err)
		}
		if seen[record.ID] || envelopes[packet.EventID] || record.User != "root" || record.SourceIP != "192.0.2.4" || !record.LoginTime.Equal(at) {
			t.Fatalf("same-second logins were merged, duplicated or changed: %+v", record)
		}
		seen[record.ID], envelopes[packet.EventID] = true, true
	}
	if !seen["session-one"] || !seen["session-two"] || scans.Load() != 1 {
		t.Fatalf("records=%v scans=%d; login polling must not schedule full scans", seen, scans.Load())
	}
	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("service did not join its SSH worker on cancellation")
	}
}

func TestSSHRealtimePollPreservesPromAndSendsNoScanSummary(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	latest := filepath.Join(c.OutputDir, "textfile", "anqu.prom")
	put(t, c.Setup.Prom, "configured metrics must stay unchanged\n")
	put(t, latest, "latest metrics must stay unchanged\n")
	at := time.Now().UTC()
	appendSSHJSONL(t, c.Login.Path, loginJSON("ops", "poll-only", at))
	var log bytes.Buffer
	more, err := PollSSHLogins(c, &log)
	if err != nil || more {
		t.Fatalf("single-page poll: more=%v err=%v", more, err)
	}
	packets := sshRealtimePackets(t, listener, 100*time.Millisecond)
	if len(packets) != 1 || packets[0].Type != "ssh_login" {
		t.Fatalf("standalone login poll must only send login events: %+v", packets)
	}
	if read(t, c.Setup.Prom) != "configured metrics must stay unchanged\n" || read(t, latest) != "latest metrics must stay unchanged\n" {
		t.Fatal("login poll overwrote full-scan metrics")
	}
	if !strings.Contains(log.String(), `"event":"ssh_login"`) || strings.Contains(log.String(), `"event":"scan_started"`) || strings.Contains(log.String(), `"event":"scan_complete"`) {
		t.Fatalf("login poll produced incorrect local logs: %s", log.String())
	}
}

func TestSSHRealtimePollAndFullScanShareCursorAcrossRestart(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	at := time.Now().UTC().Truncate(time.Second)
	appendSSHJSONL(t, c.Login.Path, loginJSON("root", "from-scan", at))
	first, _, err := Run(c)
	if err != nil || !first.Success || len(first.Login.Records) != 1 {
		t.Fatalf("full scan did not collect first login: %+v %v", first.Login, err)
	}
	if _, err := PollSSHLogins(c, nil); err != nil {
		t.Fatal(err)
	}
	appendSSHJSONL(t, c.Login.Path, loginJSON("root", "from-poll", at))
	if _, err := PollSSHLogins(c, nil); err != nil {
		t.Fatal(err)
	}
	second, _, err := Run(c)
	if err != nil || !second.Success || len(second.Login.Records) != 0 {
		t.Fatalf("full scan repeated a login consumed by poll: %+v %v", second.Login, err)
	}
	if _, err := PollSSHLogins(NewSession(c), nil); err != nil {
		t.Fatal(err)
	}
	// Race a full scan against the independent collector using the same source.
	appendSSHJSONL(t, c.Login.Path, loginJSON("root", "concurrent-one", at)+loginJSON("root", "concurrent-two", at))
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		_, err := PollSSHLogins(c, nil)
		results <- err
	}()
	go func() {
		defer workers.Done()
		<-start
		r, _, err := Run(c)
		if err == nil && !r.Success {
			err = errors.New("concurrent full scan reported collection failure")
		}
		results <- err
	}()
	close(start)
	workers.Wait()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("shared login lock rejected a concurrent collector: %v", err)
		}
	}
	if _, err := PollSSHLogins(NewSession(c), nil); err != nil {
		t.Fatal(err)
	}
	records := sshRealtimeRecords(t, sshRealtimePackets(t, listener, 100*time.Millisecond))
	counts := map[string]int{}
	for _, record := range records {
		counts[record.ID]++
	}
	for _, id := range []string{"from-scan", "from-poll", "concurrent-one", "concurrent-two"} {
		if counts[id] != 1 {
			t.Fatalf("full scan, poll or restart repeated/lost a login: %v", counts)
		}
	}
	if len(records) != 4 {
		t.Fatalf("unexpected SSH notifications: %+v", records)
	}
}

type sshRealtimeFailedWriter struct{}

func (sshRealtimeFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("local log output unavailable")
}

func TestSSHRealtimeLocalLogFailureDoesNotConsumeCursor(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	at := time.Now().UTC()
	appendSSHJSONL(t, c.Login.Path, loginJSON("ops", "saved-login", at))
	if _, err := PollSSHLogins(c, nil); err != nil {
		t.Fatal(err)
	}
	_ = sshRealtimePackets(t, listener, 50*time.Millisecond)
	before := read(t, c.StateFile+".logins")
	appendSSHJSONL(t, c.Login.Path, loginJSON("ops", "retry-login", at))
	if _, err := PollSSHLogins(c, sshRealtimeFailedWriter{}); err == nil {
		t.Fatal("local log failure was ignored")
	}
	if read(t, c.StateFile+".logins") != before {
		t.Fatal("failed local publication consumed the login cursor")
	}
	_ = sshRealtimePackets(t, listener, 50*time.Millisecond)
	if _, err := PollSSHLogins(NewSession(c), nil); err != nil {
		t.Fatal(err)
	}
	records := sshRealtimeRecords(t, sshRealtimePackets(t, listener, 100*time.Millisecond))
	if len(records) != 1 || records[0].ID != "retry-login" {
		t.Fatalf("restart after log failure lost the unread login: %+v", records)
	}
}

func TestSSHRealtimeBacklogDrainsWithoutWaitingForPollInterval(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	c.Login.MaxRecords = 1
	c.Login.PollIntervalMS = 1500
	at := time.Now().UTC().Truncate(time.Second)
	appendSSHJSONL(t, c.Login.Path, loginJSON("ops", "page-one", at)+loginJSON("ops", "page-two", at)+loginJSON("ops", "page-three", at))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var finished bool
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(1500 * time.Millisecond):
				t.Error("SSH backlog worker did not stop")
			}
		}
	})
	go func() {
		done <- serve(ctx, c, nil, "ssh-pages-test", func(Config, io.Writer) (Report, OutputPaths, error) {
			<-ctx.Done()
			return Report{Success: true}, OutputPaths{}, nil
		})
	}()
	packets := sshRealtimePackets(t, listener, 1200*time.Millisecond)
	records := sshRealtimeRecords(t, packets)
	if len(records) != 3 || records[0].ID != "page-one" || records[1].ID != "page-two" || records[2].ID != "page-three" {
		t.Fatalf("pending pages waited for the poll interval or lost order: %+v", records)
	}
	cancel()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("service did not stop after draining SSH pages")
	}
}

func TestSSHRealtimePollIntervalDefaultsAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        int
		valid       bool
	}{
		{"default", "", 1000, true},
		{"zero-default", "  poll_interval_ms: 0\n", 1000, true},
		{"minimum", "  poll_interval_ms: 100\n", 100, true},
		{"too-fast", "  poll_interval_ms: 99\n", 0, false},
		{"too-slow", "  poll_interval_ms: 60001\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseConfig([]byte("output_dir: output\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin:\n  enabled: true\n  source: jsonl\n  path: login.jsonl\n"+tc.field), t.TempDir())
			if (err == nil) != tc.valid || (err == nil && c.Login.PollIntervalMS != tc.want) {
				t.Fatalf("poll interval=%d err=%v", c.Login.PollIntervalMS, err)
			}
		})
	}
}

func TestSSHRealtimeIdlePollDoesNotRewriteEncryptedCursor(t *testing.T) {
	for _, source := range []string{"jsonl", "authlog"} {
		t.Run(source, func(t *testing.T) {
			c := sshRealtimeConfig(t)
			c.Login.Source = source
			var output bytes.Buffer
			if _, err := PollSSHLogins(c, &output); err != nil {
				t.Fatal(err)
			}
			before := read(t, c.StateFile+".logins")
			for i := 0; i < 3; i++ {
				if more, err := PollSSHLogins(c, &output); err != nil || more {
					t.Fatalf("idle poll: more=%v err=%v", more, err)
				}
			}
			if read(t, c.StateFile+".logins") != before || output.Len() != 0 {
				t.Fatal("idle login polling rewrote state or produced per-second logs")
			}
		})
	}
}

func TestSSHRealtimeLoginLockWaitIsCancelable(t *testing.T) {
	c := sshRealtimeConfig(t)
	unlock, err := lockSSHLoginState(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := pollSSHLogins(ctx, c, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("login lock wait did not honor cancellation: %v", err)
	}
}

func TestSSHRealtimeCancellationDuringUDPSend(t *testing.T) {
	listener := heartbeatListener(t)
	c := sshRealtimeConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	done := make(chan []NotificationResult, 1)
	go func() {
		done <- sendUDPContext(ctx, c, func(string) ([][]byte, error) {
			close(started) // The outgoing UDP socket is already connected.
			<-ctx.Done()
			return [][]byte{[]byte("must not send after cancellation")}, nil
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("UDP send did not start")
	}
	cancel()
	select {
	case result := <-done:
		if len(result) != 1 || result[0].Sent != 0 || result[0].Error == "" {
			t.Fatalf("canceled UDP send was reported as successful: %+v", result)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("UDP send did not stop promptly")
	}
	if packets := sshRealtimePackets(t, listener, 50*time.Millisecond); len(packets) != 0 {
		t.Fatal("a packet was sent to the old target after cancellation")
	}
}
