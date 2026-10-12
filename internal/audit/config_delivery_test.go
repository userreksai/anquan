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
	"testing"
	"time"

	"anqu/internal/sealed"
)

func deliveryBootstrap(t *testing.T) (Config, string) {
	t.Helper()
	base := t.TempDir()
	cfg, err := ParseConfig([]byte("output_dir: local\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\nserver: [127.0.0.1:55555]\nagent_ip: 192.0.2.21\nsetup:\n  logs: local/logs/agent.log\n  prom: local/agent.prom\n  interval_seconds: 30\n"), base)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = BootstrapConfig(cfg, base, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, base
}

func assignedFrame(t *testing.T, output string) configFrame {
	t.Helper()
	data := "output_dir: " + output + "\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\nserver: [127.0.0.1:22222]\nagent_ip: 192.0.2.99\nsetup:\n  logs: " + output + "/logs/agent.log\n  prom: " + output + "/agent.prom\n  interval_seconds: 2\n"
	ciphertext, err := sealed.EncryptConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return configFrame{Version: 1, Type: "config", Revision: configRevision(ciphertext), Ciphertext: string(ciphertext)}
}

func commitAssignment(cfg Config, commit func() error) error { return commit() }

func TestAssignedConfigPersistsEncryptedAndKeepsBootstrapIdentity(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "test")
	frame := assignedFrame(t, "remote")
	if err := d.accept(frame, commitAssignment); err != nil {
		t.Fatal(err)
	}
	if d.current.OutputDir != filepath.Join(base, "remote") || d.current.reportedIP() != cfg.reportedIP() || len(d.current.Server) != 1 || d.current.Server[0] != "127.0.0.1:22222" || d.current.masters[0] != cfg.masters[0] {
		t.Fatalf("assignment overwrote bootstrap identity: %+v", d.current)
	}
	stored, err := os.ReadFile(d.cachePath())
	if err != nil || string(stored) != frame.Ciphertext || bytes.Contains(stored, []byte("output_dir")) {
		t.Fatalf("cache does not contain ciphertext only: %v", err)
	}
	restarted := NewConfigDelivery(cfg, base, "test")
	got, err := restarted.CachedConfig()
	if err != nil || got.OutputDir != d.current.OutputDir || restarted.revision != frame.Revision {
		t.Fatalf("cached assignment was not restored: %+v %v", got, err)
	}
	restarted.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }
	got, err = restarted.Sync(context.Background())
	if err != nil || got.OutputDir != d.current.OutputDir {
		t.Fatal("master outage discarded the last valid assignment")
	}
	if err := restarted.accept(configFrame{Version: 1, Type: "config"}, commitAssignment); err != nil {
		t.Fatal(err)
	}
	if restarted.current.OutputDir != cfg.OutputDir || restarted.revision != "" {
		t.Fatal("unassigned agent did not return to local configuration")
	}
	if _, err := os.Stat(restarted.cachePath()); !os.IsNotExist(err) {
		t.Fatal("unassignment did not remove cached master configuration")
	}
}

func TestInvalidAssignmentAndFailedActivationKeepPreviousConfig(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "test")
	previous := assignedFrame(t, "valid")
	if err := d.accept(previous, commitAssignment); err != nil {
		t.Fatal(err)
	}
	badYAML, err := sealed.EncryptConfig([]byte("private_secret: PRIVATE_CONFIG_MARKER\n"))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []configFrame{
		{Revision: previous.Revision, Ciphertext: "damaged"},
		{Revision: configRevision([]byte("plaintext")), Ciphertext: "plaintext"},
		{Revision: configRevision(badYAML), Ciphertext: string(badYAML)},
		{Revision: previous.Revision},
	}
	for _, frame := range invalid {
		err := d.accept(frame, func(Config, func() error) error { t.Fatal("invalid assignment reached service"); return nil })
		if err == nil || strings.Contains(err.Error(), "PRIVATE_CONFIG_MARKER") {
			t.Fatalf("invalid assignment accepted or echoed secrets: %v", err)
		}
	}
	if err := d.accept(assignedFrame(t, "blocked"), func(Config, func() error) error { return errors.New("runtime setup rejected") }); err == nil {
		t.Fatal("activation failure was acknowledged as successful")
	}
	if d.revision != previous.Revision || read(t, d.cachePath()) != previous.Ciphertext {
		t.Fatal("rejected update replaced previous assignment")
	}
}

func TestSingleSyncDoesNotWriteCacheControlledByRunningService(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "test")
	assigned := assignedFrame(t, "cached")
	if err := d.accept(assigned, commitAssignment); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockState(d.cachePath() + ".service.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("single check opened a competing configuration connection")
		return nil, nil
	}
	got, err := d.Sync(context.Background())
	if err == nil || got.OutputDir != filepath.Join(base, "cached") || read(t, d.cachePath()) != assigned.Ciphertext {
		t.Fatalf("single check changed service configuration: %+v %v", got, err)
	}
}

type scanCancelWriter struct {
	cancel  context.CancelFunc
	scanned bool
}

func (w *scanCancelWriter) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"event":"scan_complete"`)) {
		w.scanned = true
		w.cancel()
	}
	return len(data), nil
}

func TestOfflineAgentDoesNotRequireWritableExecutableDirectory(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	cfg.Server = nil
	cfg.masters = nil
	programDir := filepath.Join(base, "program")
	d := NewConfigDelivery(cfg, programDir, "test")
	// A directory at the would-be lock filename makes any attempt to open it
	// fail on Windows and Unix, without depending on root/ACL permission rules.
	lockPath := d.cachePath() + ".service.lock"
	if err := os.MkdirAll(lockPath, 0700); err != nil {
		t.Fatal(err)
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("offline agent attempted to contact a master")
		return nil, nil
	}
	if got, err := d.Sync(context.Background()); err != nil || got.OutputDir != cfg.OutputDir {
		t.Fatalf("offline single check accessed configuration lock: %+v %v", got, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writer := &scanCancelWriter{cancel: cancel}
	if err := ServeWithConfigDelivery(ctx, cfg, writer, "test", d); err != nil {
		t.Fatalf("offline service accessed configuration lock: %v", err)
	}
	if !writer.scanned {
		t.Fatal("offline service did not complete its initial scan")
	}
	entries, err := os.ReadDir(programDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(lockPath) || !entries[0].IsDir() {
		t.Fatalf("offline agent changed executable directory: %v %v", entries, err)
	}
}

func TestConfigDeliveryUsesBoundedFramesAndRepliesWithFailedACK(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "test")
	d.ping = time.Hour
	for _, oversized := range []bool{false, true} {
		agentConn, masterConn := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan error, 1)
		go func() { done <- d.connection(ctx, agentConn, d.endpoints[0], true, commitAssignment) }()
		decoder := json.NewDecoder(masterConn)
		var hello configFrame
		if err := decoder.Decode(&hello); err != nil || hello.Type != "hello" || hello.Version != 1 || !hello.DiscoverIP || hello.IP != "" || hello.Host == "" || hello.AgentVersion != "test" {
			t.Fatalf("invalid hello: %+v %v", hello, err)
		}
		if oversized {
			go func() { _, _ = io.WriteString(masterConn, strings.Repeat("x", maxConfigFrameBytes+1)+"\n") }()
		} else {
			if err := json.NewEncoder(masterConn).Encode(configFrame{Version: 1, Type: "config", Revision: "invalid", Ciphertext: "invalid"}); err != nil {
				t.Fatal(err)
			}
			var ack configFrame
			if err := decoder.Decode(&ack); err != nil || ack.Type != "ack" || ack.Revision != "invalid" || ack.Error == "" {
				t.Fatalf("bad configuration did not produce failed ACK: %+v %v", ack, err)
			}
		}
		if err := <-done; err == nil {
			t.Fatal("bad or oversized assignment accepted")
		}
		cancel()
		_ = masterConn.Close()
	}
}

func TestServiceConfigDeliveryReloadsWithoutRestartAndMaintainsPingDuringScan(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "reload-test")
	d.ping, d.retry = 20*time.Millisecond, time.Hour
	agentConn, masterConn := net.Pipe()
	defer masterConn.Close()
	var dialOnce sync.Once
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		var result net.Conn
		dialOnce.Do(func() { result = agentConn })
		if result == nil {
			return nil, errors.New("offline")
		}
		return result, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := make(chan Config, 5)
	blocked, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseScan := func() { releaseOnce.Do(func() { close(release) }) }
	var blockOnce sync.Once
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serveRuntime(ctx, cfg, &output, "reload-test", func(c Config, _ io.Writer) (Report, OutputPaths, error) {
			scans <- c
			if filepath.Base(c.OutputDir) == "first" {
				blockOnce.Do(func() { close(blocked); <-release })
			}
			return Report{Success: true}, OutputPaths{}, nil
		}, 10*time.Millisecond, d)
	}()
	defer func() {
		releaseScan()
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("service did not stop")
		}
	}()
	decoder := json.NewDecoder(masterConn)
	encoder := json.NewEncoder(masterConn)
	_ = masterConn.SetDeadline(time.Now().Add(5 * time.Second))
	var frame configFrame
	if err := decoder.Decode(&frame); err != nil || frame.Type != "hello" {
		t.Fatalf("missing hello: %v %+v", err, frame)
	}
	first := assignedFrame(t, "first")
	if err := encoder.Encode(first); err != nil {
		t.Fatal(err)
	}
	readUntilACK := func(revision string) configFrame {
		t.Helper()
		for {
			var incoming configFrame
			if err := decoder.Decode(&incoming); err != nil {
				t.Fatal(err)
			}
			if incoming.Type == "ping" {
				continue
			}
			if incoming.Type != "ack" || incoming.Revision != revision {
				t.Fatalf("unexpected frame: %+v", incoming)
			}
			return incoming
		}
	}
	if ack := readUntilACK(first.Revision); ack.Error != "" {
		t.Fatal(ack.Error)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("assigned scan did not start")
	}
	second := assignedFrame(t, "second")
	if err := encoder.Encode(second); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&frame); err != nil || frame.Type != "ping" {
		t.Fatalf("configuration reload blocked keepalive: %+v %v", frame, err)
	}
	releaseScan()
	if ack := readUntilACK(second.Revision); ack.Error != "" {
		t.Fatal(ack.Error)
	}
	for _, want := range []string{"first", "second"} {
		select {
		case got := <-scans:
			if filepath.Base(got.OutputDir) != want || got.reportedIP() != cfg.reportedIP() || got.Server[0] != "127.0.0.1:22222" || got.masters[0] != cfg.masters[0] {
				t.Fatalf("scan did not use activated configuration %s: %+v", want, got)
			}
		case <-time.After(time.Second):
			t.Fatal("reloaded configuration did not scan immediately")
		}
	}
	locked := assignedFrame(t, "locked")
	lockedConfig, err := d.parseAssigned([]byte(locked.Ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(lockedConfig.StateFile), 0700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockState(lockedConfig.StateFile + ".service.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(locked); err != nil {
		unlock()
		t.Fatal(err)
	}
	ack := readUntilACK(locked.Revision)
	unlock()
	if ack.Error == "" || read(t, d.cachePath()) != second.Ciphertext {
		t.Fatal("state lock failure replaced active assignment or was acknowledged as applied")
	}
	if err := encoder.Encode(configFrame{Version: 1, Type: "config"}); err != nil {
		t.Fatal(err)
	}
	if ack := readUntilACK(""); ack.Error != "" {
		t.Fatal(ack.Error)
	}
	select {
	case got := <-scans:
		if got.OutputDir != cfg.OutputDir {
			t.Fatal("live unassignment did not restore bootstrap audit config")
		}
	case <-time.After(time.Second):
		t.Fatal("unassignment did not trigger scan")
	}
	if _, err := os.Stat(d.cachePath()); !os.IsNotExist(err) {
		t.Fatal("cache was not removed after live unassignment")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	done <- nil // Let the cleanup verify the already-completed service.
}

func TestRemoteOnlyServiceWaitsThenActivatesAndCanReturnToWaiting(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Setup.IntervalSeconds = 1
	d := NewConfigDelivery(cfg, base, "remote-only-test")
	d.ping, d.retry = time.Hour, time.Hour
	agentConn, masterConn := net.Pipe()
	defer masterConn.Close()
	var once sync.Once
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		var conn net.Conn
		once.Do(func() { conn = agentConn })
		if conn == nil {
			return nil, errors.New("offline")
		}
		return conn, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	scans := make(chan Config, 10)
	done := make(chan error, 1)
	var output bytes.Buffer
	go func() {
		done <- serveRuntime(ctx, cfg, &output, "remote-only-test", func(c Config, _ io.Writer) (Report, OutputPaths, error) {
			scans <- c
			return Report{Success: true}, OutputPaths{}, nil
		}, time.Hour, d)
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("waiting service did not stop cleanly")
		}
	}()
	_ = masterConn.SetDeadline(time.Now().Add(10 * time.Second))
	decoder, encoder := json.NewDecoder(masterConn), json.NewEncoder(masterConn)
	var hello configFrame
	if err := decoder.Decode(&hello); err != nil || hello.Type != "hello" || !hello.DiscoverIP || hello.IP != "" {
		t.Fatalf("agent did not register without a local config: %+v %v", hello, err)
	}
	send := func(frame configFrame, wantError bool) {
		t.Helper()
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
		var ack configFrame
		if err := decoder.Decode(&ack); err != nil || ack.Type != "ack" || ack.Revision != frame.Revision || (ack.Error != "") != wantError {
			t.Fatalf("unexpected assignment ACK: %+v %v", ack, err)
		}
	}
	assertPaused := func(delay time.Duration) {
		t.Helper()
		select {
		case c := <-scans:
			t.Fatalf("unconfigured agent scanned: %+v", c)
		case <-time.After(delay):
		}
	}
	send(configFrame{Version: 1, Type: "config"}, false)
	// Waiting out the old three-second startup fallback proves that no default
	// scan, worker output or state lock is created while assignment is absent.
	assertPaused(3200 * time.Millisecond)
	for _, name := range []string{"state", "logs", "textfile"} {
		if _, err := os.Stat(filepath.Join(base, name)); !os.IsNotExist(err) {
			t.Fatalf("waiting service created %s", name)
		}
	}
	bad, err := sealed.EncryptConfig([]byte("unknown_field: rejected\n"))
	if err != nil {
		t.Fatal(err)
	}
	send(configFrame{Version: 1, Type: "config", Revision: configRevision(bad), Ciphertext: string(bad)}, true)
	assertPaused(20 * time.Millisecond)
	assigned := assignedFrame(t, "assigned")
	readScan := func() {
		t.Helper()
		select {
		case c := <-scans:
			if c.WaitingForConfig() || c.OutputDir != filepath.Join(base, "assigned") || c.reportedIP() != cfg.reportedIP() || c.Server[0] != "127.0.0.1:22222" || c.masters[0] != cfg.masters[0] {
				t.Fatalf("assigned config did not replace waiting bootstrap: %+v", c)
			}
		case <-time.After(time.Second):
			t.Fatal("assignment did not start collection")
		}
	}
	send(assigned, false)
	readScan()
	if got := read(t, d.cachePath()); got != assigned.Ciphertext {
		t.Fatal("remote-only service did not persist its encrypted assignment")
	}
	send(configFrame{Version: 1, Type: "config"}, false)
	assertPaused(1100 * time.Millisecond)
	if _, err := os.Stat(d.cachePath()); !os.IsNotExist(err) {
		t.Fatal("unassignment did not clear cache")
	}
	// Reactivating the same state path requires releasing and reacquiring its
	// runtime lock when the agent returns to waiting.
	send(assigned, false)
	readScan()
	send(configFrame{Version: 1, Type: "config"}, false)
	assertPaused(20 * time.Millisecond)
}
