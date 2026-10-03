package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func heartbeatListener(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readHeartbeatPacket(t *testing.T, listener net.PacketConn) udpEnvelope {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65536)
	n, _, err := listener.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	var envelope udpEnvelope
	if err := json.Unmarshal(b[:n], &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestServiceHeartbeatArrivesBeforeAndDuringBlockedFirstScan(t *testing.T) {
	listener := heartbeatListener(t)
	c := monitoringTestConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	c.AgentIP = "10.20.30.40"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveWithHeartbeatInterval(ctx, c, nil, "heartbeat-test", func(Config, io.Writer) (Report, OutputPaths, error) {
			close(started)
			<-release
			return Report{Success: true}, OutputPaths{}, nil
		}, 20*time.Millisecond)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first scan did not start")
	}
	first := readHeartbeatPacket(t, listener)
	second := readHeartbeatPacket(t, listener)
	for _, event := range []udpEnvelope{first, second} {
		var body struct {
			Interval int    `json:"interval_seconds"`
			Version  string `json:"version"`
			State    string `json:"state"`
		}
		if err := json.Unmarshal(event.Data, &body); err != nil {
			t.Fatal(err)
		}
		if event.Type != "heartbeat" || event.IP != c.AgentIP || event.Host == "" || body.Interval != 30 || body.Version != "heartbeat-test" || body.State != "running" {
			t.Fatalf("bad heartbeat: %+v %+v", event, body)
		}
	}
	if !second.Time.After(first.Time) || second.EventID == first.EventID {
		t.Fatal("periodic heartbeat did not advance while scan was blocked")
	}
	cancel()
	// Drain any datagram already in flight at cancellation, then prove the
	// independent ticker has stopped even though the scan is still blocked.
	for {
		_ = listener.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		if _, _, err := listener.ReadFrom(make([]byte, 65536)); err != nil {
			break
		}
	}
	_ = listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := listener.ReadFrom(make([]byte, 65536)); err == nil {
		t.Fatal("heartbeat continued after cancellation")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop after scan completed")
	}
}

func TestOnceSendsStartupHeartbeatBeforeScanSummary(t *testing.T) {
	listener := heartbeatListener(t)
	c := monitoringTestConfig(t)
	c.Server = []string{listener.LocalAddr().String()}
	r, _, err := Run(c)
	if err != nil || !r.Success {
		t.Fatalf("scan failed: %+v %v", r, err)
	}
	first, second := readHeartbeatPacket(t, listener), readHeartbeatPacket(t, listener)
	if first.Type != "heartbeat" || second.Type != "scan_summary" || first.IP != "127.0.0.1" {
		t.Fatalf("startup did not precede scan report: %s %s", first.Type, second.Type)
	}
}

func TestHeartbeatFailureIsLoggedWithoutStoppingScan(t *testing.T) {
	c := monitoringTestConfig(t)
	c.Server = []string{"invalid-endpoint-without-port"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	called := false
	err := serve(ctx, c, &output, "test", func(Config, io.Writer) (Report, OutputPaths, error) {
		called = true
		cancel()
		return Report{}, OutputPaths{}, nil
	})
	if err != nil || !called || !strings.Contains(output.String(), `"event":"heartbeat_error"`) {
		t.Fatalf("heartbeat failure stopped service or was hidden: called=%v err=%v output=%s", called, err, output.String())
	}
}
