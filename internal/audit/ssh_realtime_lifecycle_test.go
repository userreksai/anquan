package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"anqu/internal/sealed"
)

func TestSSHRealtimeConfigurationSwitchAndDisable(t *testing.T) {
	listenerA, listenerB := heartbeatListener(t), heartbeatListener(t)
	bootstrap, base := deliveryBootstrap(t)
	put(t, filepath.Join(base, "login.jsonl"), "")
	delivery := NewConfigDelivery(bootstrap, base, "ssh-lifecycle-test")
	delivery.ping, delivery.retry = time.Hour, time.Hour
	agentConn, masterConn := net.Pipe()
	var dialOnce sync.Once
	delivery.dial = func(context.Context, string, string) (net.Conn, error) {
		var conn net.Conn
		dialOnce.Do(func() { conn = agentConn })
		if conn == nil {
			return nil, errors.New("test control connection already used")
		}
		return conn, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	scans := make(chan Config, 4)
	t.Cleanup(func() {
		cancel()
		_ = masterConn.Close()
		_ = agentConn.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(1500 * time.Millisecond):
			t.Error("configuration delivery did not stop its SSH worker")
		}
	})
	go func() {
		done <- serveRuntime(ctx, bootstrap, nil, "ssh-lifecycle-test", func(c Config, _ io.Writer) (Report, OutputPaths, error) {
			scans <- c
			return Report{Success: true}, OutputPaths{}, nil
		}, time.Hour, delivery)
	}()
	decoder, encoder := json.NewDecoder(masterConn), json.NewEncoder(masterConn)
	if err := masterConn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var hello configFrame
	if err := decoder.Decode(&hello); err != nil || hello.Type != "hello" {
		t.Fatalf("control connection did not register: %+v %v", hello, err)
	}
	frameFor := func(enabled bool, endpoint string) configFrame {
		t.Helper()
		yaml := fmt.Sprintf("output_dir: local\nstate_file: state/md5.json\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin:\n  enabled: %t\n  mode: poll\n  source: jsonl\n  path: login.jsonl\n  poll_interval_ms: 100\nserver: ['%s']\nsetup:\n  logs: local/logs/agent.log\n  prom: local/agent.prom\n  interval_seconds: 300\n", enabled, endpoint)
		ciphertext, err := sealed.EncryptConfig([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		return configFrame{Version: 1, Type: "config", Revision: configRevision(ciphertext), Ciphertext: string(ciphertext)}
	}
	activate := func(frame configFrame, enabled bool, endpoint string) Config {
		t.Helper()
		if err := masterConn.SetDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
		var ack configFrame
		if err := decoder.Decode(&ack); err != nil || ack.Type != "ack" || ack.Revision != frame.Revision || ack.Error != "" {
			t.Fatalf("configuration was not activated before ACK: %+v %v", ack, err)
		}
		select {
		case c := <-scans:
			if c.Login.Enabled != enabled || c.Login.Source != "jsonl" || (enabled && c.Login.Path != filepath.Join(base, "login.jsonl")) || len(c.Server) != 1 || c.Server[0] != endpoint || c.Interval() != 300*time.Second {
				t.Fatalf("scan did not use activated SSH configuration: %+v", c)
			}
			return c
		case <-time.After(1500 * time.Millisecond):
			t.Fatal("configuration activation did not reach the running service")
			return Config{}
		}
	}
	readLogin := func(listener net.PacketConn, id string) {
		t.Helper()
		if err := listener.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		for {
			buf := make([]byte, 65536)
			n, _, err := listener.ReadFrom(buf)
			if err != nil {
				t.Fatalf("active SSH worker did not send %s: %v", id, err)
			}
			var packet udpEnvelope
			if err := json.Unmarshal(buf[:n], &packet); err != nil {
				t.Fatal(err)
			}
			if packet.Type == "heartbeat" {
				continue
			}
			var record LoginRecord
			if err := json.Unmarshal(packet.Data, &record); err != nil {
				t.Fatal(err)
			}
			if packet.Type != "ssh_login" || record.ID != id {
				t.Fatalf("old worker or cursor replay emitted an unexpected event: %+v %+v", packet, record)
			}
			return
		}
	}
	waitCommitted := func(c Config, id string) {
		t.Helper()
		deadline := time.Now().Add(1500 * time.Millisecond)
		for {
			var state loginBaseline
			err := readState(c.StateFile+".logins", "login", &state)
			if err == nil && state.Latest != nil && state.Latest.ID == id {
				return
			}
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("UDP arrived before login cursor could be committed: latest=%+v err=%v", state.Latest, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	assertNoLogins := func(listener net.PacketConn, reason string) {
		t.Helper()
		for _, packet := range sshRealtimePackets(t, listener, 350*time.Millisecond) {
			if packet.Type == "ssh_login" {
				t.Fatalf("%s: %+v", reason, packet)
			}
		}
	}
	activeA := activate(frameFor(true, listenerA.LocalAddr().String()), true, listenerA.LocalAddr().String())
	at := time.Now().UTC().Truncate(time.Second)
	appendSSHJSONL(t, activeA.Login.Path, loginJSON("root", "on-A", at))
	readLogin(listenerA, "on-A")
	// Sending UDP precedes durable cursor publication. Wait for that commit so
	// this test isolates worker replacement instead of legitimate crash retry.
	waitCommitted(activeA, "on-A")
	activeB := activate(frameFor(true, listenerB.LocalAddr().String()), true, listenerB.LocalAddr().String())
	if activeB.StateFile != activeA.StateFile || activeB.Login.Path != activeA.Login.Path {
		t.Fatal("server switch changed the source or login state path")
	}
	appendSSHJSONL(t, activeB.Login.Path, loginJSON("root", "on-B", at))
	readLogin(listenerB, "on-B")
	waitCommitted(activeB, "on-B")
	assertNoLogins(listenerA, "previous server still received logins after configuration ACK")
	disabled := activate(frameFor(false, listenerB.LocalAddr().String()), false, listenerB.LocalAddr().String())
	before := read(t, disabled.StateFile+".logins")
	appendSSHJSONL(t, activeB.Login.Path, loginJSON("root", "disabled-login", at))
	assertNoLogins(listenerA, "old worker remained active after disabling SSH collection")
	assertNoLogins(listenerB, "disabled SSH worker still sent appended logins")
	if read(t, disabled.StateFile+".logins") != before {
		t.Fatal("disabled worker still consumed the login source")
	}
}
