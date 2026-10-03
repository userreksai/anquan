package audit

import (
	"context"
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
	return serve(ctx, c, writer, version, func(c Config, writer io.Writer) (Report, OutputPaths, error) {
		return runWithWriter(c, writer, false)
	})
}

func serve(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error)) error {
	return serveWithHeartbeatInterval(ctx, c, writer, version, scan, HeartbeatInterval)
}

func serveWithHeartbeatInterval(ctx context.Context, c Config, writer io.Writer, version string, scan func(Config, io.Writer) (Report, OutputPaths, error), heartbeatInterval time.Duration) error {
	if c.Interval() <= 0 {
		return fmt.Errorf("check interval must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
		return err
	}
	unlock, err := lockState(c.StateFile + ".service.lock")
	if err != nil {
		return err
	}
	defer unlock()
	// Heartbeat errors and scan output may be written concurrently. os.Stdout
	// already supports that, while embedded callers may supply a bytes.Buffer.
	if writer != nil {
		writer = &lockedWriter{writer: writer}
	}
	if err := LifecycleLog(c, writer, "service_started", map[string]any{"version": version, "pid": os.Getpid(), "interval_seconds": c.Interval().Seconds()}); err != nil {
		return err
	}
	if ctx.Err() == nil {
		heartbeatOnce(c, writer, version)
	}
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		heartbeatLoop(heartbeatCtx, c, writer, version, heartbeatInterval)
	}()
	defer func() { cancelHeartbeat(); <-heartbeatDone }()
	ticker := time.NewTicker(c.Interval())
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return LifecycleLog(c, writer, "service_stopped", map[string]string{"reason": ctx.Err().Error()})
		}
		// RunWithWriter persists detailed failure logs. Errors never stop later checks.
		if _, _, err := scan(c, writer); err != nil && writer != nil {
			fmt.Fprintf(writer, "audit failed: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return LifecycleLog(c, writer, "service_stopped", map[string]string{"reason": ctx.Err().Error()})
		case <-ticker.C:
		}
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
