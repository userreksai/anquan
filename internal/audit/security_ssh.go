package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"anqu/internal/security"
)

type sshFailureWindow struct {
	Times     []time.Time `json:"times"`
	LastAlert time.Time   `json:"last_alert"`
}

type sshFailureState struct {
	Version int                         `json:"version"`
	Since   time.Time                   `json:"since"`
	Cursor  string                      `json:"cursor"`
	Sources map[string]sshFailureWindow `json:"sources"`
}

var failedSSH = regexp.MustCompile(`\bFailed (\S+) for (?:invalid user )?(\S+) from (\S+) port ([0-9]+)(?:\s|$)`)

func parseSSHFailurePage(reader io.Reader, cfg SecuritySSHAuthConfig, state *sshFailureState, emit func(security.Event) error) (bool, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	processed := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var entry journalLoginEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return false, err
		}
		micros, err := strconv.ParseInt(entry.Timestamp, 10, 64)
		if err != nil || entry.Cursor == "" {
			return false, fmt.Errorf("invalid SSH journal timestamp/cursor")
		}
		at := time.UnixMicro(micros).UTC()
		match := failedSSH.FindStringSubmatch(entry.Message)
		if match != nil {
			ip := net.ParseIP(match[3])
			port, err := strconv.Atoi(match[4])
			if ip == nil || err != nil || port < 1 || port > 65535 {
				return false, fmt.Errorf("invalid failed SSH address/port")
			}
			data := map[string]any{"source": "ssh_auth", "kind": "ssh_auth_failure", "severity": "info", "message": "SSH authentication failed", "user": match[2], "source_ip": ip.String(), "source_port": port, "method": match[1], "details": map[string]any{"journal_cursor": entry.Cursor}}
			if err := emit(security.Event{ID: "ssh-failure:" + entry.Cursor, Type: "security_event", Time: at, Component: "ssh_auth", Data: data}); err != nil {
				return false, err
			}
			if state.Sources == nil {
				state.Sources = map[string]sshFailureWindow{}
			}
			window := state.Sources[ip.String()]
			cutoff := at.Add(-time.Duration(cfg.WindowSeconds) * time.Second)
			var retained []time.Time
			for _, t := range window.Times {
				if !t.Before(cutoff) {
					retained = append(retained, t)
				}
			}
			window.Times = append(retained, at)
			if len(window.Times) >= cfg.AlertThreshold && (window.LastAlert.IsZero() || at.Sub(window.LastAlert) >= time.Duration(cfg.WindowSeconds)*time.Second) {
				alert := map[string]any{"source": "ssh_auth", "kind": "ssh_bruteforce", "severity": "warning", "message": "repeated SSH authentication failures", "source_ip": ip.String(), "user": match[2], "details": map[string]any{"count": len(window.Times), "window_seconds": cfg.WindowSeconds, "journal_cursor": entry.Cursor}}
				if err := emit(security.Event{ID: "ssh-bruteforce:" + entry.Cursor, Type: "security_event", Time: at, Component: "ssh_auth", Data: alert}); err != nil {
					return false, err
				}
				window.LastAlert = at
			}
			if len(window.Times) > cfg.AlertThreshold*2 {
				window.Times = window.Times[len(window.Times)-cfg.AlertThreshold*2:]
			}
			state.Sources[ip.String()] = window
		}
		state.Cursor = entry.Cursor
		processed++
		if processed%100 == 0 {
			for ip, window := range state.Sources {
				if len(window.Times) == 0 || window.Times[len(window.Times)-1].Before(at.Add(-time.Duration(cfg.WindowSeconds)*time.Second)) {
					delete(state.Sources, ip)
				}
			}
			if len(state.Sources) > 10000 {
				return false, fmt.Errorf("SSH failure window exceeds 10000 source IPs")
			}
		}
		if processed >= 1000 {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func pollSSHFailures(ctx context.Context, c Config, emit func(security.Event) error) (bool, error) {
	path := filepath.Join(securityDataDir(c), "ssh-failures.state")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	unlock, err := lockState(path + ".lock")
	if err != nil {
		return false, err
	}
	defer unlock()
	state := sshFailureState{}
	if err := readState(path, "ssh-failures", &state); err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		state = sshFailureState{Version: 1, Since: time.Now().Add(-time.Duration(c.Security.SSHAuth.InitialLookbackSeconds) * time.Second), Sources: map[string]sshFailureWindow{}}
	}
	if state.Version != 1 {
		return false, fmt.Errorf("invalid SSH failure cursor")
	}
	before := state.Cursor
	command := c.Login.JournalCommand
	if command == "" {
		command = "journalctl"
	}
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(readCtx, command, journalArgs(LoginConfig{}, &loginBaseline{Since: state.Since, JournalCursor: state.Cursor})...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	stderr := &cappedBuffer{max: 65536}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err = cmd.Start(); err != nil {
		return false, err
	}
	more, parseErr := parseSSHFailurePage(stdout, *c.Security.SSHAuth, &state, emit)
	if more || parseErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return false, parseErr
	}
	if readCtx.Err() != nil {
		return false, readCtx.Err()
	}
	if waitErr != nil && !more {
		return false, fmt.Errorf("read SSH failure journal: %w; %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return false, fmt.Errorf("SSH journal warning: %s", strings.TrimSpace(stderr.String()))
	}
	if state.Cursor == before {
		return more, nil
	}
	return more, writeState(path, "ssh-failures", state)
}

func sshFailuresLoop(ctx context.Context, c Config, emit func(security.Event) error, health func(error)) {
	if runtime.GOOS != "linux" {
		health(errors.New("SSH failure journal collection requires Linux systemd"))
		return
	}
	lastReport := time.Time{}
	for ctx.Err() == nil {
		more, err := pollSSHFailures(ctx, c, emit)
		health(err)
		if err != nil && ctx.Err() == nil && time.Since(lastReport) >= time.Minute {
			lastReport = time.Now()
			_ = emit(security.Event{ID: "ssh-failure-reader:" + lastReport.UTC().Format("20060102T1504"), Type: "security_event", Time: lastReport, Component: "ssh_auth", Data: map[string]any{"source": "ssh_auth", "kind": "collector_error", "severity": "error", "message": err.Error()}})
		}
		if more && err == nil {
			continue
		}
		timer := time.NewTimer(time.Duration(c.Security.SSHAuth.PollIntervalSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
