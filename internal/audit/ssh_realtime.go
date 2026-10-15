package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// Login checks share this resource with one-shot scans and legacy migration,
// independently of the potentially slow file/process scan lock.
func lockSSHLoginState(parent context.Context, c Config) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
		return nil, err
	}
	timeout := c.Login.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		unlock, err := lockState(c.StateFile + ".logins.lock")
		if err == nil {
			return unlock, nil
		}
		if !errors.Is(err, errStateLockBusy) {
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// PollSSHLogins collects a bounded page without running file/process checks or
// overwriting their metrics. True means another page may remain to be drained.
func PollSSHLogins(c Config, writer io.Writer) (bool, error) {
	return pollSSHLogins(context.Background(), c, writer)
}

func pollSSHLogins(ctx context.Context, c Config, writer io.Writer) (bool, error) {
	if !c.Login.Enabled || c.waitingForConfig {
		return false, nil
	}
	if c.location == nil {
		return false, fmt.Errorf("configuration must be loaded with LoadConfig")
	}
	unlock, err := lockSSHLoginState(ctx, c)
	if err != nil {
		return false, err
	}
	defer unlock()
	statePath := c.StateFile + ".logins"
	if err := protectLegacyState(statePath, "login"); err != nil {
		return false, err
	}
	var before loginBaseline
	existing := true
	if err := readState(statePath, "login", &before); os.IsNotExist(err) {
		existing = false
	} else if err != nil {
		return false, err
	}
	// Empty Seen maps are omitted in encrypted JSON. Normalize their decoded
	// form so an idle poll does not rewrite the same cursor every second.
	if before.Seen == nil {
		before.Seen = map[string]int{}
	}
	now := time.Now().In(c.location)
	result, next, issues := collectSSHLoginsContext(ctx, c, now)
	if len(issues) > 0 {
		var failures []error
		for _, issue := range issues {
			failures = append(failures, fmt.Errorf("%s: %s", issue.Module, issue.Message))
		}
		return false, errors.Join(failures...)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var sendErr error
	if len(result.Records) > 0 {
		// Keep local evidence before advancing the shared durable cursor.
		if err := writeLog(c, writer, now, "login_result", result); err != nil {
			return false, err
		}
		for _, record := range result.Records {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if err := writeLog(c, writer, now, "ssh_login", record); err != nil {
				return false, err
			}
		}
		host, err := os.Hostname()
		if err != nil {
			return false, err
		}
		notifications := notifySSHLogins(ctx, c, host, result.Records)
		if err := writeLog(c, writer, time.Now(), "ssh_poll_complete", struct {
			Logins        int                  `json:"logins"`
			Pending       bool                 `json:"pending"`
			Notifications []NotificationResult `json:"notifications"`
		}{len(result.Records), result.Pending, notifications}); err != nil {
			return false, err
		}
		var failures []error
		for _, notification := range notifications {
			if notification.Error != "" {
				failures = append(failures, fmt.Errorf("%s: %s", notification.Server, notification.Error))
			}
		}
		sendErr = errors.Join(failures...)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if next != nil && (!existing || !reflect.DeepEqual(before, *next)) {
		if err := writeState(statePath, "login", next); err != nil {
			return false, err
		}
	}
	// UDP retains its existing best-effort semantics. Local send errors are
	// logged, without replaying an entire page into the logs every second.
	return result.Pending, sendErr
}

func notifySSHLogins(ctx context.Context, c Config, host string, records []LoginRecord) []NotificationResult {
	return sendUDPContext(ctx, c, func(ip string) ([][]byte, error) {
		messages := make([][]byte, 0, len(records))
		for _, record := range records {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			message, err := encodeUDPEvent(ip, host, "ssh_login", record.LoginTime, record.ID, record)
			if err != nil {
				return nil, err
			}
			messages = append(messages, message)
		}
		return messages, nil
	})
}

func sshLoginLoop(ctx context.Context, c Config, writer io.Writer) {
	if !c.Login.Enabled {
		return
	}
	interval := c.Login.PollIntervalMS
	if interval == 0 {
		interval = 1000
	}
	var lastError string
	var lastReport time.Time
	for ctx.Err() == nil {
		more, err := pollSSHLogins(ctx, c, writer)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if lastError == "" || time.Since(lastReport) >= time.Minute {
				_ = writeLog(c, writer, time.Now(), "ssh_login_error", map[string]string{"source": c.Login.Source, "error": err.Error()})
				lastError, lastReport = err.Error(), time.Now()
			}
		} else {
			lastError = ""
		}
		if more && err == nil {
			continue
		}
		timer := time.NewTimer(time.Duration(interval) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
