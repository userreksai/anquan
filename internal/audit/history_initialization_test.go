package audit

import (
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
)

func TestHistoryInitializerCompletesBeforeServiceScan(t *testing.T) {
	cfg, _ := deliveryBootstrap(t)
	cfg.Server = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var order []string
	err := serveRuntimeWithHistoryInitializer(ctx, cfg, nil, "history-init-test", func(c Config, _ io.Writer) (Report, OutputPaths, error) {
		order = append(order, "scan")
		cancel()
		return Report{Success: true}, OutputPaths{}, nil
	}, time.Hour, nil, func(c Config, _ io.Writer) error {
		if c.StateFile != cfg.StateFile {
			t.Errorf("initializer received another configuration: %s", c.StateFile)
		}
		order = append(order, "initialize")
		return nil
	})
	if err != nil || strings.Join(order, ",") != "initialize,scan" {
		t.Fatalf("initialization must finish once before collection: order=%v err=%v", order, err)
	}
}

func TestHistoryInitializerFailurePreventsServiceCollection(t *testing.T) {
	cfg, _ := deliveryBootstrap(t)
	cfg.Server = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called, scanned := 0, false
	err := serveRuntimeWithHistoryInitializer(ctx, cfg, nil, "history-init-test", func(Config, io.Writer) (Report, OutputPaths, error) {
		scanned = true
		cancel()
		return Report{}, OutputPaths{}, nil
	}, time.Hour, nil, func(Config, io.Writer) error {
		called++
		return errors.New("history script repair denied")
	})
	if err == nil || !strings.Contains(err.Error(), "history script repair denied") || called != 1 || scanned {
		t.Fatalf("failed initialization must stop startup: called=%d scanned=%v err=%v", called, scanned, err)
	}
}

func TestWaitingServiceDoesNotInitializeHistory(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	called, scanned := false, false
	err = serveRuntimeWithHistoryInitializer(ctx, cfg, nil, "history-init-test", func(Config, io.Writer) (Report, OutputPaths, error) {
		scanned = true
		return Report{}, OutputPaths{}, nil
	}, time.Hour, nil, func(Config, io.Writer) error {
		called = true
		return nil
	})
	if err != nil || called || scanned {
		t.Fatalf("unassigned service initialized or collected: called=%v scanned=%v err=%v", called, scanned, err)
	}
	if _, err := os.Stat(filepath.Dir(cfg.StateFile)); !os.IsNotExist(err) {
		t.Fatalf("waiting service created history state directory: %v", err)
	}
}

func TestHistoryInitializationFailureRejectsAssignmentAndKeepsPreviousCache(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(cfg, base, "history-init-test")
	d.ping, d.retry = time.Hour, time.Hour
	agentConn, masterConn := net.Pipe()
	defer masterConn.Close()
	var dialOnce sync.Once
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		var conn net.Conn
		dialOnce.Do(func() { conn = agentConn })
		if conn == nil {
			return nil, errors.New("offline")
		}
		return conn, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	scans := make(chan string, 5)
	initializations := make(chan string, 5)
	done := make(chan error, 1)
	denyOnce := true
	go func() {
		done <- serveRuntimeWithHistoryInitializer(ctx, cfg, nil, "history-init-test", func(c Config, _ io.Writer) (Report, OutputPaths, error) {
			scans <- filepath.Base(c.OutputDir)
			return Report{Success: true}, OutputPaths{}, nil
		}, time.Hour, d, func(c Config, _ io.Writer) error {
			name := filepath.Base(c.OutputDir)
			initializations <- name
			if name == "repair-denied" && denyOnce {
				denyOnce = false
				return errors.New("history script repair denied")
			}
			return nil
		})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("service did not stop after history initialization test")
		}
	}()
	if err := masterConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	decoder, encoder := json.NewDecoder(masterConn), json.NewEncoder(masterConn)
	var hello configFrame
	if err := decoder.Decode(&hello); err != nil || hello.Type != "hello" {
		t.Fatalf("missing service hello: %+v %v", hello, err)
	}
	sendAssignment := func(frame configFrame) configFrame {
		t.Helper()
		if err := encoder.Encode(frame); err != nil {
			t.Fatal(err)
		}
		var ack configFrame
		if err := decoder.Decode(&ack); err != nil || ack.Type != "ack" || ack.Revision != frame.Revision {
			t.Fatalf("unexpected assignment response: %+v %v", ack, err)
		}
		return ack
	}
	readName := func(ch <-chan string, want string) {
		t.Helper()
		select {
		case got := <-ch:
			if got != want {
				t.Fatalf("configuration name=%s, want %s", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("configuration %s did not reach expected lifecycle stage", want)
		}
	}
	first := assignedFrame(t, "previous")
	if ack := sendAssignment(first); ack.Error != "" {
		t.Fatal(ack.Error)
	}
	readName(initializations, "previous")
	readName(scans, "previous")
	if got := read(t, d.cachePath()); got != first.Ciphertext {
		t.Fatal("successful assignment was not persisted")
	}
	denied := assignedFrame(t, "repair-denied")
	if ack := sendAssignment(denied); !strings.Contains(ack.Error, "history script repair denied") {
		t.Fatalf("history initialization failure was not reported in ACK: %+v", ack)
	}
	readName(initializations, "repair-denied")
	if got := read(t, d.cachePath()); got != first.Ciphertext {
		t.Fatal("failed history initialization replaced the previous encrypted assignment")
	}
	// The previous schedule remains active after failed activation, rather than
	// proceeding with the rejected configuration or leaving collection stopped.
	readName(scans, "previous")
	select {
	case name := <-initializations:
		t.Fatalf("old worker restart repeated initialization unexpectedly: %s", name)
	default:
	}
	// Retrying the same revision succeeds once repair is possible. This also
	// proves the failed attempt released the next state lock and did not mark
	// the rejected revision as already applied.
	if ack := sendAssignment(denied); ack.Error != "" {
		t.Fatal(ack.Error)
	}
	readName(initializations, "repair-denied")
	readName(scans, "repair-denied")
	if got := read(t, d.cachePath()); got != denied.Ciphertext {
		t.Fatal("valid assignment after history failure was not persisted")
	}
}
