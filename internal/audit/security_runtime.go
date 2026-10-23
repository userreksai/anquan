package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"anqu/internal/security"
)

func boundedSecurityStatusText(value any, limit int) any {
	s, ok := value.(string)
	if !ok || len(s) <= limit {
		return value
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Policy inspection can contain large sudo -l output. Keep basic health
// deliverable even when the optional details would exceed the UDP budget.
func boundSecurityStatus(data map[string]any, components []map[string]any) {
	for _, component := range components {
		for _, key := range []string{"message", "error", "version"} {
			component[key] = boundedSecurityStatusText(component[key], 2048)
		}
		checks, ok := component["checks"].([]any)
		if !ok {
			continue
		}
		if len(checks) > 64 {
			component["omitted_checks"] = len(checks) - 64
			checks = checks[:64]
			component["checks"] = checks
		}
		for _, check := range checks {
			if fields, ok := check.(map[string]any); ok {
				for _, key := range []string{"setting", "expected", "actual", "message", "error"} {
					if value, ok := fields[key].(string); ok && len(value) > 512 {
						fields[key] = boundedSecurityStatusText(value, 512)
						fields["truncated"] = true
					}
				}
			}
		}
	}
	data["components"] = components
	raw, _ := json.Marshal(data)
	if len(raw) <= 48000 {
		return
	}
	data["details_truncated"] = true
	for _, component := range components {
		if checks, ok := component["checks"].([]any); ok {
			omitted, _ := component["omitted_checks"].(int)
			component["omitted_checks"] = omitted + len(checks)
			delete(component, "checks")
		}
		for _, key := range []string{"message", "error", "version"} {
			component[key] = boundedSecurityStatusText(component[key], 256)
		}
	}
	if initialization, ok := data["initialization_error"].(map[string]any); ok {
		initialization["error"] = boundedSecurityStatusText(initialization["error"], 256)
	}
}

// Component ownership and source cursors belong to the installation rather
// than to the replaceable report output_dir/state_file fields in a profile.
func securityDataDir(c Config) string {
	if c.runtimeDir != "" {
		return filepath.Join(c.runtimeDir, "state", "security")
	}
	return filepath.Join(filepath.Dir(c.StateFile), "security")
}

func securityInventory() map[string]any {
	result := map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "cpu_count": runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		result["kernel"] = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		release := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok && (key == "ID" || key == "VERSION_ID" || key == "PRETTY_NAME") {
				release[key] = strings.Trim(value, "\"'")
			}
		}
		result["distribution"] = release
	}
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	result["btf_available"] = err == nil
	return result
}

func componentConfig(c Config) security.Config {
	if c.Security != nil {
		return c.Security.Config
	}
	var cfg security.Config
	cfg.Normalize()
	return cfg
}

// Component configuration is applied before the normal assignment ACK. A
// failed validation/reload keeps the previous encrypted assignment active.
func applySecurityComponents(ctx context.Context, c Config, writer io.Writer) error {
	manager := security.NewManager(componentConfig(c), securityDataDir(c))
	manager.DownloadRelay = c.downloadRelay
	statuses, err := manager.Apply(ctx)
	return recordSecurityApplyResult(c, writer, statuses, err)
}

func recordSecurityApplyResult(c Config, writer io.Writer, statuses []security.ComponentStatus, err error) error {
	if err != nil {
		_ = writeState(filepath.Join(securityDataDir(c), "apply-error.state"), "security-apply-error", map[string]any{"error": err.Error(), "components": statuses, "attempted_at": time.Now().UTC()})
		_ = writeLog(c, writer, time.Now(), "security_apply_failed", map[string]any{"error": err.Error(), "components": statuses})
		return fmt.Errorf("security component initialization failed: %w", err)
	}
	if removeErr := os.Remove(filepath.Join(securityDataDir(c), "apply-error.state")); removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return nil
}

func securityLoop(ctx context.Context, c Config, writer io.Writer) {
	if c.Security == nil {
		if _, err := os.Stat(filepath.Join(securityDataDir(c), "outbox")); os.IsNotExist(err) {
			return
		}
	}
	q, err := openSecurityQueue(c)
	if err != nil {
		_ = writeLog(c, writer, time.Now(), "security_error", map[string]string{"error": err.Error()})
		return
	}
	var healthMu sync.Mutex
	fimState := "disabled"
	fimError := ""
	sshState, sshError := "disabled", ""
	taskState, taskError := "disabled", ""
	sshEnabled := c.Security != nil && c.Security.Enabled && c.Security.SSHAuth != nil && c.Security.SSHAuth.Enabled
	if sshEnabled {
		sshState = "starting"
	}
	inventory := securityInventory()
	fimEnabled := c.Security != nil && c.Security.Enabled && c.Security.NativeFIM != nil && c.Security.NativeFIM.Enabled
	if fimEnabled {
		fimState = "starting"
	}
	statusReporter := &componentStatusReporter{snapshotInterval: componentStatusSnapshotPeriod(componentConfig(c).StatusIntervalSeconds)}
	persist := func(event security.Event) error {
		if err := q.enqueue(c, event); err != nil {
			return err
		}
		// I/O payload stays encrypted in the outbox, not duplicated in plaintext logs.
		if event.Data["kind"] != "io_chunk" {
			_ = writeLog(c, writer, event.Time, event.Type, event.Data)
		}
		return nil
	}
	emit := func(event security.Event) error {
		if event.Type == "component_status" {
			if event.Data == nil {
				event.Data = map[string]any{}
			}
			// Marshal the engine's typed slice before appending a native component.
			var components []map[string]any
			b, _ := json.Marshal(event.Data["components"])
			_ = json.Unmarshal(b, &components)
			healthMu.Lock()
			components = append(components, map[string]any{"name": "native_fim", "enabled": fimEnabled, "installed": true, "running": fimState == "running", "state": fimState, "error": fimError})
			components = append(components, map[string]any{"name": "ssh_auth", "enabled": sshEnabled, "installed": runtime.GOOS == "linux", "running": sshState == "running", "state": sshState, "message": sshError})
			components = append(components, map[string]any{"name": "task_wrapper", "enabled": c.Security != nil && c.Security.Enabled, "installed": true, "running": taskState == "ready", "state": taskState, "message": taskError})
			var initializationError map[string]any
			_ = readState(filepath.Join(securityDataDir(c), "apply-error.state"), "security-apply-error", &initializationError)
			if initializationError != nil {
				components = append(components, map[string]any{"name": "initialization", "enabled": true, "installed": false, "running": false, "state": "error", "message": boundedSecurityStatusText(initializationError["error"], 4096)})
				event.Data["initialization_error"] = map[string]any{"error": boundedSecurityStatusText(initializationError["error"], 4096), "attempted_at": initializationError["attempted_at"]}
			}
			healthMu.Unlock()
			event.Data["queue"] = q.stats()
			event.Data["inventory"] = inventory
			boundSecurityStatus(event.Data, components)
			return statusReporter.emit(event, persist)
		}
		return persist(event)
	}
	if c.Security == nil || !c.Security.Enabled {
		if err := applySecurityComponents(ctx, c, writer); err != nil && ctx.Err() != nil {
			return
		}
		manager := security.NewManager(componentConfig(c), securityDataDir(c))
		manager.DownloadRelay = c.downloadRelay
		_ = emit(security.Event{Type: "component_status", Time: time.Now().UTC(), Data: map[string]any{"components": manager.Status(ctx)}})
	}
	var workers sync.WaitGroup
	if c.Security != nil && c.Security.Enabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			// Initial cached assignments may need slow package installation.
			// Keep the configuration connection and heartbeats alive meanwhile.
			_ = applySecurityComponents(ctx, c, writer)
			manager := security.NewManager(c.Security.Config, securityDataDir(c))
			manager.DownloadRelay = c.downloadRelay
			manager.ReconcileResult = func(statuses []security.ComponentStatus, err error) error {
				return recordSecurityApplyResult(c, writer, statuses, err)
			}
			for ctx.Err() == nil {
				if err := manager.Run(ctx, emit); err != nil && ctx.Err() == nil {
					_ = writeLog(c, writer, time.Now(), "security_error", map[string]string{"error": err.Error()})
				}
				timer := time.NewTimer(5 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
				case <-timer.C:
				}
			}
		}()
		workers.Add(1)
		go func() {
			defer workers.Done()
			taskResultsLoop(ctx, c, emit, func(err error) {
				healthMu.Lock()
				defer healthMu.Unlock()
				taskState = "ready"
				taskError = ""
				if err != nil {
					taskState = "error"
					taskError = err.Error()
				}
			})
		}()
	}
	if sshEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			sshFailuresLoop(ctx, c, emit, func(err error) {
				healthMu.Lock()
				defer healthMu.Unlock()
				sshState = "running"
				sshError = ""
				if err != nil {
					sshState = "error"
					sshError = err.Error()
				}
			})
		}()
	}
	if fimEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			nativeFIMLoop(ctx, c, emit, func(err error) {
				healthMu.Lock()
				defer healthMu.Unlock()
				fimState = "running"
				fimError = ""
				if err != nil {
					fimState = "error"
					fimError = err.Error()
				}
			})
		}()
	}
	var lastError string
	var lastReport time.Time
	for ctx.Err() == nil {
		more, err := q.drain(ctx, c, sendSecurityToMaster)
		if err != nil && ctx.Err() == nil && (err.Error() != lastError || time.Since(lastReport) > time.Minute) {
			lastError = err.Error()
			lastReport = time.Now()
			_ = writeLog(c, writer, time.Now(), "security_delivery_error", map[string]any{"error": err.Error(), "queue": q.stats()})
		}
		if err == nil {
			lastError = ""
		}
		delay := time.Second
		if more && err == nil {
			delay = 10 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	workers.Wait()
}
