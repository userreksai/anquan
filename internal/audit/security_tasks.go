package audit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"anqu/internal/sealed"
	"anqu/internal/security"
)

const taskOutputLimit = 8 << 10
const maxTaskSpoolFiles = 1000
const maxTaskSpoolBytes int64 = 64 << 20

var taskNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// taskOutput preserves the business command's output even when the audit
// capture is full. A failed destination is reported after the command exits;
// it must not close the process pipe and interrupt an otherwise valid task.
type taskOutput struct {
	writer    io.Writer
	mu        *sync.Mutex
	data      []byte
	truncated bool
	err       error
}

func (w *taskOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := taskOutputLimit - len(w.data)
	if remaining > 0 {
		n := len(p)
		if n > remaining {
			n = remaining
		}
		w.data = append(w.data, p[:n]...)
	}
	if len(p) > remaining {
		w.truncated = true
	}
	if w.writer != nil {
		n, err := w.writer.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if w.err == nil {
			w.err = err
		}
	}
	return len(p), nil
}

func taskSpoolDirectory(baseDir string) string {
	return filepath.Join(baseDir, "state", "security", "task-spool")
}

// spoolTaskEvent stores only encrypted bytes, using a stable lock outside the
// directory that the service consumes. Busy/full/broken storage is deliberately
// an audit error rather than a reason to skip the business command.
func spoolTaskEvent(baseDir string, event security.Event, phase string) error {
	dir := taskSpoolDirectory(baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	unlock, err := lockState(filepath.Join(filepath.Dir(dir), "task-spool.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	count := 0
	var size int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("task spool contains a non-regular file")
		}
		count++
		size += info.Size()
	}
	// Encode before the final byte-limit check so the encrypted record itself
	// cannot exceed the remaining capacity.
	data, err := marshalTaskEvent(event)
	if err != nil {
		return err
	}
	defer clear(data)
	if count >= maxTaskSpoolFiles || size+int64(len(data)) > maxTaskSpoolBytes {
		return fmt.Errorf("task spool full (files=%d, bytes=%d)", count, size)
	}
	invocation, _ := event.Data["invocation_id"].(string)
	name := event.Time.UTC().Format("20060102T150405.000000000") + "-" + invocation + "-" + phase + ".age"
	return atomicWrite(filepath.Join(dir, name), data, 0600)
}

func marshalTaskEvent(event security.Event) ([]byte, error) {
	// Reuse the state serializer without creating a plaintext staging file.
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return sealed.SealState(data, "security-task")
}

// RunRecordedTask executes exactly argv, without a shell. The exit code always
// belongs to the task, including when audit storage fails. Validation failures
// return 2, a missing executable returns 127, another launch failure returns
// 126, and a process terminated without an exit status returns 1.
//
// Output is forwarded unchanged and captured as at most 8 KiB per stream. The
// encrypted records use Base64 so binary output and JSON escaping stay bounded.
func RunRecordedTask(ctx context.Context, baseDir, name string, args []string, stdout, stderr io.Writer) (int, error) {
	if !taskNamePattern.MatchString(name) {
		return 2, errors.New("task name must be 1..64 ASCII letters, digits, '.', '_', ':' or '-', starting with a letter or digit")
	}
	if len(args) == 0 || !filepath.IsAbs(args[0]) || strings.ContainsRune(args[0], 0) {
		return 2, errors.New("task command must be an absolute executable path")
	}
	var invocationBytes [16]byte
	randomErr := error(nil)
	if _, err := rand.Read(invocationBytes[:]); err != nil {
		// A recording failure cannot suppress execution. There is no event
		// identity to persist safely if secure randomness itself is unavailable.
		randomErr = fmt.Errorf("create task invocation identity: %w", err)
	}
	invocation := hex.EncodeToString(invocationBytes[:])
	argv, argvTruncated := boundedTaskArgv(args)
	started := time.Now().UTC()
	event := func(kind, severity, message string, at time.Time, details map[string]any) security.Event {
		return security.Event{ID: "task:" + invocation + ":" + kind, Type: "security_event", Time: at, Component: "task", Message: message, Data: map[string]any{
			"source": "task", "kind": kind, "severity": severity, "message": message,
			"task_name": name, "invocation_id": invocation, "command": argv[0], "argv": argv, "argv_truncated": argvTruncated, "details": details,
		}}
	}
	var recordingErrors []error
	if randomErr != nil {
		recordingErrors = append(recordingErrors, randomErr)
	} else if err := spoolTaskEvent(baseDir, event("task_started", "info", "Scheduled task started", started, map[string]any{"started_at": started}), "start"); err != nil {
		recordingErrors = append(recordingErrors, fmt.Errorf("record task start: %w", err))
	}
	var outputMu sync.Mutex
	out := &taskOutput{writer: stdout, mu: &outputMu}
	errout := &taskOutput{writer: stderr, mu: &outputMu}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = out, errout
	runErr := cmd.Run()
	finished := time.Now().UTC()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.As(runErr, &exitErr):
			exitCode = exitErr.ExitCode()
			if exitCode < 0 {
				exitCode = 1
			}
		case errors.Is(runErr, os.ErrNotExist), errors.Is(runErr, exec.ErrNotFound):
			exitCode = 127
		default:
			exitCode = 126
		}
	}
	kind, severity, message := "task_finished", "info", "Scheduled task finished"
	if runErr != nil {
		kind, severity, message = "task_failed", "warning", "Scheduled task failed"
	}
	details := map[string]any{
		"started_at": started, "finished_at": finished, "elapsed_ms": finished.Sub(started).Milliseconds(),
		"exit_code": exitCode, "failed": runErr != nil, "output_encoding": "base64",
		"stdout_base64": base64.StdEncoding.EncodeToString(out.data), "stderr_base64": base64.StdEncoding.EncodeToString(errout.data),
		"stdout_truncated": out.truncated, "stderr_truncated": errout.truncated,
	}
	if runErr != nil {
		details["error"] = boundedTaskText(runErr.Error(), 1024)
	}
	if ctx.Err() != nil {
		details["cancelled"] = true
	}
	if randomErr == nil {
		if err := spoolTaskEvent(baseDir, event(kind, severity, message, finished, details), "finish"); err != nil {
			recordingErrors = append(recordingErrors, fmt.Errorf("record task finish: %w", err))
		}
	}
	if out.err != nil {
		recordingErrors = append(recordingErrors, fmt.Errorf("forward task stdout: %w", out.err))
	}
	if errout.err != nil {
		recordingErrors = append(recordingErrors, fmt.Errorf("forward task stderr: %w", errout.err))
	}
	// Ordinary nonzero exits are fully represented by exitCode and the event.
	// Launch/cancellation errors also have useful diagnostics for CLI stderr.
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		recordingErrors = append(recordingErrors, runErr)
	}
	return exitCode, errors.Join(recordingErrors...)
}

func boundedTaskText(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.ToValidUTF8(s, "�")
}

func boundedTaskArgv(args []string) ([]string, bool) {
	result := make([]string, 0, min(len(args), 256))
	// Command metadata has a separate cap. It can appear twice (command/argv)
	// and JSON may expand a control character to six bytes; together with both
	// Base64 output captures the event must remain below the transport limit.
	remaining := 1024
	truncated := false
	for _, arg := range args {
		if len(result) >= 256 || remaining == 0 {
			truncated = true
			break
		}
		if len(arg) > remaining {
			result = append(result, boundedTaskText(arg, remaining))
			truncated = true
			break
		}
		result = append(result, strings.ToValidUTF8(arg, "�"))
		remaining -= len(arg)
	}
	return result, truncated
}
