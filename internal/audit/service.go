package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Serve runs immediately, then on each interval without overlapping scans.
// Collection failures are recorded and retried; SIGTERM cancellation stops the
// schedule after the current bounded collection finishes.
func Serve(ctx context.Context, c Config, writer io.Writer, version string) error {
	return serve(ctx, NewSession(c), writer, version, func(c Config, writer io.Writer) (Report, OutputPaths, error) {
		return runWithWriter(c, writer, false)
	})
}

// ServeWithConfigDelivery keeps an outbound master connection while collecting.
// Updates activate between scans; cancellation joins every independent worker.
func ServeWithConfigDelivery(ctx context.Context, c Config, writer io.Writer, version string, delivery *ConfigDelivery) error {
	if delivery == nil || len(delivery.endpoints) == 0 {
		return Serve(ctx, c, writer, version)
	}
	unlock, err := lockService(delivery.cachePath())
	if err != nil {
		return err
	}
	defer unlock()
	if err := delivery.persistConnectionSettings(); err != nil {
		return err
	}
	return serveRuntime(ctx, NewSession(c), writer, version, func(c Config, writer io.Writer) (Report, OutputPaths, error) {
		return runWithWriter(c, writer, false)
	}, HeartbeatInterval, delivery)
}

func serve(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error)) error {
	return serveWithHeartbeatInterval(ctx, c, writer, version, scan, HeartbeatInterval)
}

func serveWithHeartbeatInterval(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error), heartbeatInterval time.Duration) error {
	return serveRuntime(ctx, c, writer, version, scan, heartbeatInterval, nil)
}

func serveRuntime(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error), heartbeatInterval time.Duration, delivery *ConfigDelivery) error {
	return serveRuntimeWithHistoryInitializer(ctx, c, writer, version, scan, heartbeatInterval, delivery, initializeHistoryScript)
}

func serveRuntimeWithHistoryInitializer(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error), heartbeatInterval time.Duration, delivery *ConfigDelivery, initialize func(Config, io.Writer) error) error {
	c.realtimeLogin = true
	if c.Interval() <= 0 {
		return fmt.Errorf("check interval must be positive")
	}
	unlock := func() {}
	if !c.waitingForConfig {
		if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
			return err
		}
		var err error
		unlock, err = lockService(c.StateFile)
		if err != nil {
			return err
		}
	}
	defer func() { unlock() }()
	// Heartbeat errors and scan output may be written concurrently. os.Stdout
	// already supports that, while embedded callers may supply a bytes.Buffer.
	if writer != nil {
		writer = &lockedWriter{writer: writer}
	}
	if !c.waitingForConfig {
		if err := initialize(c, writer); err != nil {
			return err
		}
	}
	if c.waitingForConfig {
		logWaitingForConfig(writer)
	} else {
		if err := LifecycleLog(c, writer, "service_started", map[string]any{"version": version, "pid": os.Getpid(), "interval_seconds": c.Interval().Seconds()}); err != nil {
			return err
		}
		if ctx.Err() == nil {
			heartbeatOnce(c, writer, version)
		}
	}
	startWorkers := func(cfg Config) func() {
		if cfg.waitingForConfig {
			return func() {}
		}
		workerCtx, cancel := context.WithCancel(ctx)
		var workers sync.WaitGroup
		workers.Add(4)
		go func() {
			defer workers.Done()
			securityLoop(workerCtx, cfg, writer)
		}()
		go func() {
			defer workers.Done()
			heartbeatLoop(workerCtx, cfg, writer, version, heartbeatInterval)
		}()
		go func() {
			defer workers.Done()
			historyLoop(workerCtx, cfg, writer)
		}()
		go func() {
			defer workers.Done()
			if cfg.Login.Mode == "poll" {
				sshLoginLoop(workerCtx, cfg, writer)
			} else if cfg.Login.Enabled {
				if err := serveSSHExecutions(workerCtx, cfg, writer); err != nil && workerCtx.Err() == nil {
					_ = writeLog(cfg, writer, time.Now(), "ssh_execution_error", map[string]string{"error": err.Error()})
				}
			}
		}()
		return func() { cancel(); workers.Wait() }
	}
	stopWorkers := startWorkers(c)
	defer func() { stopWorkers() }()
	var updates chan configUpdate
	if delivery != nil {
		updates = make(chan configUpdate)
		deliveryCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); delivery.run(deliveryCtx, updates) }()
		defer func() { cancel(); <-done }()
	}
	var ticker *time.Ticker
	var ticks <-chan time.Time
	resetTicker := func() {
		if ticker != nil {
			ticker.Stop()
		}
		ticks = nil
		if !c.waitingForConfig {
			ticker = time.NewTicker(c.Interval())
			ticks = ticker.C
		}
	}
	resetTicker()
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	scanPending := !c.waitingForConfig
	var startup <-chan time.Time
	if !c.waitingForConfig && delivery != nil && len(delivery.endpoints) > 0 {
		// Allow a reachable master to select the initial audit configuration.
		// ACKs still go through this running service's activation path.
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		startup = timer.C
	}
	stopped := func() error {
		if c.waitingForConfig {
			return nil
		}
		return LifecycleLog(c, writer, "service_stopped", map[string]string{"reason": ctx.Err().Error()})
	}
	for {
		if ctx.Err() != nil {
			return stopped()
		}
		// RunWithWriter persists detailed failure logs. Errors never stop later checks.
		if scanPending && startup == nil {
			if _, _, err := scan(c, writer); err != nil && writer != nil {
				fmt.Fprintf(writer, "audit failed: %v\n", err)
			}
			scanPending = false
		}
		select {
		case <-ctx.Done():
			return stopped()
		case <-ticks:
			scanPending = true
		case <-startup:
			startup = nil
		case update := <-updates:
			next := update.config
			var nextUnlock func()
			var applyErr error
			if !next.waitingForConfig {
				applyErr = os.MkdirAll(filepath.Dir(next.StateFile), 0700)
				if applyErr == nil && (c.waitingForConfig || nativePathRules().key(next.StateFile) != nativePathRules().key(c.StateFile)) {
					nextUnlock, applyErr = lockService(next.StateFile)
				}
				if applyErr == nil {
					applyErr = LifecycleLog(next, writer, "configuration_validated", map[string]any{"interval_seconds": next.Interval().Seconds()})
				}
			}
			if applyErr != nil {
				if nextUnlock != nil {
					nextUnlock()
				}
				update.result <- fmt.Errorf("configuration runtime setup failed")
				continue
			}
			// Old workers must release history cursor locks before the next set
			// starts. Cache failure restarts the original workers unchanged.
			stopWorkers()
			if !next.waitingForConfig {
				if err := initialize(next, writer); err != nil {
					if nextUnlock != nil {
						nextUnlock()
					}
					stopWorkers = startWorkers(c)
					update.result <- err
					continue
				}
			}
			if next.Security != nil || c.Security != nil {
				if err := applySecurityComponents(ctx, next, writer); err != nil {
					if nextUnlock != nil {
						nextUnlock()
					}
					stopWorkers = startWorkers(c)
					update.result <- err
					continue
				}
			}
			if err := update.commit(); err != nil {
				if nextUnlock != nil {
					nextUnlock()
				}
				if next.Security != nil || c.Security != nil {
					if restoreErr := applySecurityComponents(ctx, c, writer); restoreErr != nil {
						err = errors.Join(err, fmt.Errorf("previous component configuration restoration failed: %w", restoreErr))
						_ = LifecycleLog(c, writer, "security_rollback_failed", map[string]string{"error": restoreErr.Error()})
					}
				}
				stopWorkers = startWorkers(c)
				update.result <- err
				continue
			}
			if next.waitingForConfig {
				unlock()
				unlock = func() {}
			} else if nextUnlock != nil {
				unlock()
				unlock = nextUnlock
			}
			c = NewSession(next)
			c.realtimeLogin = true
			startup = nil
			stopWorkers = startWorkers(c)
			resetTicker()
			scanPending = !c.waitingForConfig
			if c.waitingForConfig {
				logWaitingForConfig(writer)
			} else {
				_ = LifecycleLog(c, writer, "configuration_applied", map[string]any{"interval_seconds": c.Interval().Seconds()})
			}
			update.result <- nil
		}
	}
}

func logWaitingForConfig(writer io.Writer) {
	if writer != nil {
		fmt.Fprintln(writer, "waiting for master configuration; connected agents can be selected in the platform; collection is paused")
	}
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(b)
}

func heartbeatOnce(c Config, writer io.Writer, version string) {
	for _, result := range NotifyHeartbeat(c, version) {
		if result.Error == "" {
			continue
		}
		if err := writeLog(c, writer, time.Now(), "heartbeat_error", result); err != nil && writer != nil {
			fmt.Fprintf(writer, "heartbeat logging failed: %v\n", err)
		}
	}
}

func heartbeatLoop(ctx context.Context, c Config, writer io.Writer, version string, interval time.Duration) {
	if len(c.Server) == 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			heartbeatOnce(c, writer, version)
		}
	}
}
