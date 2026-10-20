package security

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (m *Manager) runAPT(ctx context.Context, args ...string) (string, error) {
	return runAPTWithLockRetry(ctx, m.Runner, 2*time.Minute, 2*time.Second, args...)
}

// APT's lists lock is independent of DPkg::Lock::Timeout. Retry only explicit
// contention, without changing the command's normal timeout after it gets a lock.
func runAPTWithLockRetry(ctx context.Context, runner Runner, waitBudget, retryInterval time.Duration, args ...string) (string, error) {
	// Override a locally configured (possibly infinite) dpkg wait. Both update
	// and install use the same bounded, cancellable retry policy below.
	commandArgs := append([]string{"-o", "DPkg::Lock::Timeout=0"}, args...)
	var deadline time.Time
	var output string
	var lastErr error
	timedOut := func() (string, error) {
		cause := lastErr
		if detail := strings.TrimSpace(output); detail != "" && !strings.Contains(cause.Error(), detail) {
			cause = fmt.Errorf("%w: %s", cause, detail)
		}
		return output, fmt.Errorf("timed out waiting %s for APT package manager lock: %w", waitBudget, cause)
	}
	for {
		if err := ctx.Err(); err != nil {
			return output, err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return timedOut()
		}
		var err error
		output, err = runner.Run(ctx, "apt-get", commandArgs...)
		if cancelErr := ctx.Err(); cancelErr != nil {
			return output, cancelErr
		}
		if err == nil || !aptLockBusy(output+"\n"+err.Error()) {
			return output, err
		}
		lastErr = err
		if deadline.IsZero() {
			deadline = time.Now().Add(waitBudget)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return timedOut()
		}
		delay := retryInterval
		if delay <= 0 || delay > remaining {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return output, ctx.Err()
		case <-timer.C:
		}
	}
}

func aptLockBusy(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		// Permission, read-only filesystem, and other lock failures must remain
		// immediately visible rather than being mistaken for another installer.
		if !strings.Contains(line, "it is held by process ") && !strings.Contains(line, "resource temporarily unavailable") {
			continue
		}
		for _, path := range []string{"/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"} {
			for _, separator := range []string{". ", " - "} {
				if strings.Contains(line, "could not get lock "+path+separator) {
					return true
				}
			}
		}
	}
	return false
}
