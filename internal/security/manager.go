package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Time      time.Time      `json:"time"`
	Component string         `json:"component,omitempty"`
	Message   string         `json:"message,omitempty"`
	Data      map[string]any `json:"data"`
}
type ComponentStatus struct {
	Name       string        `json:"name"`
	Enabled    bool          `json:"enabled"`
	Installed  bool          `json:"installed"`
	Running    bool          `json:"running"`
	State      string        `json:"state"`
	Message    string        `json:"message"`
	Version    string        `json:"version,omitempty"`
	ConfigHash string        `json:"config_hash,omitempty"`
	AppliedAt  *time.Time    `json:"applied_at,omitempty"`
	Checks     []PolicyCheck `json:"checks,omitempty"`
}

// Runner is replaceable in tests. Commands never pass configuration through a shell.
type Runner interface {
	Run(context.Context, string, ...string) (string, error)
	LookPath(string) (string, error)
}
type commandRunner struct{}

func (commandRunner) LookPath(n string) (string, error) { return exec.LookPath(n) }
func (commandRunner) Run(ctx context.Context, n string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, n, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	b, err := cmd.CombinedOutput()
	if len(b) > 32768 {
		b = b[len(b)-32768:]
	}
	if err != nil {
		return string(b), fmt.Errorf("%s %v: %w: %s", n, args, err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

type Manager struct {
	Config    Config
	OutputDir string
	// RootDir/Runner exist for hermetic tests; production uses / and exec.CommandContext.
	RootDir   string
	Runner    Runner
	mu        sync.Mutex
	statuses  []ComponentStatus
	appliedAt *time.Time
	versions  map[string]string
}

func NewManager(cfg Config, outputDir string) *Manager {
	cfg.Normalize()
	return &Manager{Config: cfg, OutputDir: outputDir, RootDir: string(filepath.Separator), Runner: commandRunner{}, versions: map[string]string{}}
}
func (m *Manager) path(p string) string {
	return filepath.Join(m.RootDir, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}
func (m *Manager) statePath() string { return filepath.Join(m.OutputDir, "security-collector.state") }
func hashString(s string) string     { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func configHash(c Config) string     { b, _ := json.Marshal(c); return hashString(string(b)) }
func newEvent(source, kind, severity, message, key string, data map[string]any) Event {
	if data == nil {
		data = map[string]any{}
	}
	data["source"] = source
	data["kind"] = kind
	data["severity"] = severity
	data["message"] = message
	return Event{ID: hashString(source + "\x00" + kind + "\x00" + key), Type: "security_event", Time: time.Now().UTC(), Component: source, Message: message, Data: data}
}
func (m *Manager) status(ctx context.Context, name string, enabled bool) ComponentStatus {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := ComponentStatus{Name: name, Enabled: enabled, State: "disabled", Message: "disabled"}
	if !enabled {
		return s
	}
	binary := name
	if name == "auditd" {
		binary = "auditctl"
	}
	if name == "policies" {
		s.Installed = true
		s.State = "audit"
		s.Message = "host policies are checked without enforcement"
		s.Checks = m.checkPolicies(ctx)
		if m.Config.Policies.Mode == "enforce" {
			s.State = "applied"
			s.Message = "typed policies applied"
		}
		for _, check := range s.Checks {
			if !check.Compliant {
				s.State = "drift"
				s.Message = "one or more requested policies do not match effective host settings"
			}
		}
		return s
	}
	binaryPath, err := m.Runner.LookPath(binary)
	s.Installed = err == nil
	if !s.Installed {
		s.State = "missing"
		s.Message = "component is not installed"
		return s
	}
	if version, ok := m.versions[name]; ok {
		s.Version = version
	} else {
		if name == "tetragon" {
			version = m.tetragonVersion(ctx, binaryPath)
		} else {
			args := []string{"--version"}
			if name == "auditd" {
				args = []string{"-v"}
			}
			if out, err := m.Runner.Run(ctx, binary, args...); err == nil {
				version = strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
				if len(version) > 200 {
					version = version[:200]
				}
			}
		}
		// Failed and empty probes must be retried on the next status report.
		if version != "" {
			m.versions[name] = version
		}
		s.Version = version
	}
	if name == "sudo" {
		s.Running = true
		s.State = "ready"
		s.Message = "sudo available; I/O logging covers sudo-managed commands only"
		if len(m.Config.Sudo.Grants) > 0 {
			s.Message += "; existing broad grants may still permit wider access"
		}
		return s
	}
	_, err = m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", name)
	s.Running = err == nil
	if s.Running {
		s.State = "running"
		s.Message = "service running"
	} else {
		s.State = "stopped"
		s.Message = "service is not running"
	}
	return s
}
func (m *Manager) Status(ctx context.Context) []ComponentStatus {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	if runtime.GOOS != "linux" && m.RootDir == string(filepath.Separator) {
		return []ComponentStatus{{Name: "security", Enabled: m.Config.Enabled, State: "unsupported", Message: "Linux host security components are unavailable on this platform"}}
	}
	persisted, persistErr := m.loadManifest()
	if persistErr == nil {
		m.appliedAt = persisted.AppliedAt
	}
	statuses := []ComponentStatus{m.status(ctx, "auditd", m.Config.Enabled && m.Config.Auditd.Enabled), m.status(ctx, "tetragon", m.Config.Enabled && m.Config.Tetragon.Enabled), m.status(ctx, "sudo", m.Config.Enabled && m.Config.Sudo.Enabled), m.status(ctx, "policies", m.Config.Enabled)}
	for i := range statuses {
		for _, old := range m.statuses {
			if old.Name == statuses[i].Name && old.State == "error" {
				statuses[i].State = old.State
				statuses[i].Message = old.Message
				break
			}
		}
		statuses[i].ConfigHash = configHash(m.Config)
		statuses[i].AppliedAt = m.appliedAt
	}
	for p, want := range persisted.Files {
		b, err := os.ReadFile(m.path(p))
		if err == nil && hashString(string(b)) == want {
			continue
		}
		component := "policies"
		switch {
		case p == auditRulesPath:
			component = "auditd"
		case p == sudoConfigPath:
			component = "sudo"
		case strings.Contains(p, "tetragon"):
			component = "tetragon"
		}
		for i := range statuses {
			if statuses[i].Name == component {
				statuses[i].State = "drift"
				statuses[i].Message = "managed configuration changed or disappeared: " + p
			}
		}
	}
	for i := range statuses {
		if !statuses[i].Enabled || !statuses[i].Running {
			continue
		}
		p := ""
		if statuses[i].Name == "auditd" {
			p = m.auditLogPath()
		}
		if statuses[i].Name == "tetragon" {
			p = "/var/log/tetragon/tetragon.log"
		}
		if p != "" {
			if _, err := os.Stat(m.path(p)); err != nil {
				statuses[i].State = "degraded"
				statuses[i].Message = "service is running but event log is unavailable: " + p
			}
		}
	}
	if m.Config.Enabled && m.Config.Auditd.Enabled {
		if out, err := m.Runner.Run(ctx, "auditctl", "-s"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) == 2 && f[0] == "lost" && f[1] != "0" {
					for i := range statuses {
						if statuses[i].Name == "auditd" {
							statuses[i].State = "degraded"
							statuses[i].Message = "kernel audit events lost=" + f[1]
						}
					}
				}
			}
		}
	}
	return statuses
}
func (m *Manager) statusEvent(ctx context.Context) Event {
	now := time.Now().UTC()
	return Event{ID: hashString("status:" + now.Format(time.RFC3339Nano)), Type: "component_status", Time: now, Data: map[string]any{"components": m.Status(ctx), "config_hash": configHash(m.Config)}}
}

// Run expects emit to durably enqueue an event before returning nil. File
// cursors advance only after every event in that checkpoint is accepted.
func (m *Manager) Run(ctx context.Context, emit func(Event) error) error {
	if !m.Config.Enabled {
		return nil
	}
	if emit == nil {
		return errors.New("security event callback is required")
	}
	poll := time.NewTicker(time.Duration(m.Config.PollIntervalSeconds) * time.Second)
	defer poll.Stop()
	status := time.NewTicker(time.Duration(m.Config.StatusIntervalSeconds) * time.Second)
	defer status.Stop()
	// Queue backpressure is retried without consuming source cursors.
	if err := emit(m.statusEvent(ctx)); err != nil {
		return fmt.Errorf("enqueue component status: %w", err)
	}
	for {
		if err := m.Poll(ctx, emit); err != nil {
			e := newEvent("security", "collector_error", "error", err.Error(), err.Error()+time.Now().UTC().Format("2006-01-02T15:04"), nil)
			_ = emit(e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-status.C:
			if err := emit(m.statusEvent(ctx)); err != nil {
				return fmt.Errorf("enqueue component status: %w", err)
			}
		case <-poll.C:
		}
	}
}
