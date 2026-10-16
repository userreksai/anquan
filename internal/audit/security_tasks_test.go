package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"anqu/internal/sealed"
	"anqu/internal/security"
)

func TestRecordedTaskHelperProcess(t *testing.T) {
	if os.Getenv("ANQU_TEST_RECORDED_TASK_HELPER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(99)
	}
	switch args[0] {
	case "literal":
		fmt.Fprint(os.Stdout, args[1])
		fmt.Fprint(os.Stderr, "task stderr")
		code, _ := strconv.Atoi(args[2])
		os.Exit(code)
	case "large":
		fmt.Fprint(os.Stdout, strings.Repeat("o", taskOutputLimit+79))
		fmt.Fprint(os.Stderr, strings.Repeat("e", taskOutputLimit+53))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		os.Exit(98)
	}
}

func recordedTaskHelper(t *testing.T, args ...string) []string {
	t.Helper()
	t.Setenv("ANQU_TEST_RECORDED_TASK_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{executable, "-test.run=^TestRecordedTaskHelperProcess$", "--"}, args...)
}

func readTaskSpool(t *testing.T, base string) []security.Event {
	t.Helper()
	entries, err := os.ReadDir(taskSpoolDirectory(base))
	if err != nil {
		t.Fatal(err)
	}
	var events []security.Event
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".age") {
			t.Fatalf("unexpected task spool file %s", entry.Name())
		}
		b, err := os.ReadFile(filepath.Join(taskSpoolDirectory(base), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !sealed.IsState(b) || bytes.Contains(b, []byte("task stderr")) {
			t.Fatal("task event is not encrypted")
		}
		var event security.Event
		if err := readState(filepath.Join(taskSpoolDirectory(base), entry.Name()), "security-task", &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	return events
}

func TestRecordedTaskPreservesExitAndLiteralArguments(t *testing.T) {
	base := t.TempDir()
	literal := "$(never-execute); a && b | c > output"
	args := recordedTaskHelper(t, "literal", literal, "7")
	var stdout, stderr bytes.Buffer
	code, err := RunRecordedTask(context.Background(), base, "backup.daily", args, &stdout, &stderr)
	if code != 7 || err != nil {
		t.Fatalf("original exit status not preserved: %d %v", code, err)
	}
	if stdout.String() != literal || stderr.String() != "task stderr" {
		t.Fatalf("output changed: %q %q", stdout.String(), stderr.String())
	}
	events := readTaskSpool(t, base)
	if len(events) != 2 || events[0].Data["kind"] != "task_started" || events[1].Data["kind"] != "task_failed" {
		t.Fatalf("unexpected task events: %+v", events)
	}
	if events[0].ID == events[1].ID || events[0].Data["invocation_id"] != events[1].Data["invocation_id"] {
		t.Fatal("start/finish event identities are not associated")
	}
	details := events[1].Data["details"].(map[string]any)
	if details["exit_code"] != float64(7) || details["failed"] != true || details["elapsed_ms"].(float64) < 0 {
		t.Fatalf("wrong completion metadata: %+v", details)
	}
	captured, err := base64.StdEncoding.DecodeString(details["stdout_base64"].(string))
	if err != nil || string(captured) != literal {
		t.Fatalf("capture changed: %q %v", captured, err)
	}
	if details["stdout_truncated"] != false || details["stderr_truncated"] != false {
		t.Fatal("short output marked truncated")
	}
}

func TestRecordedTaskCaptureIsBoundedAndOutputIsComplete(t *testing.T) {
	base := t.TempDir()
	var stdout, stderr bytes.Buffer
	code, err := RunRecordedTask(context.Background(), base, "large", recordedTaskHelper(t, "large"), &stdout, &stderr)
	if code != 0 || err != nil {
		t.Fatalf("task failed: %d %v", code, err)
	}
	if stdout.Len() != taskOutputLimit+79 || stderr.Len() != taskOutputLimit+53 {
		t.Fatal("business output was truncated")
	}
	events := readTaskSpool(t, base)
	if events[1].Data["kind"] != "task_finished" {
		t.Fatal("successful task not recorded as finished")
	}
	details := events[1].Data["details"].(map[string]any)
	for _, stream := range []string{"stdout", "stderr"} {
		b, err := base64.StdEncoding.DecodeString(details[stream+"_base64"].(string))
		if err != nil || len(b) != taskOutputLimit || details[stream+"_truncated"] != true {
			t.Fatalf("invalid %s capture", stream)
		}
	}
}

func TestRecordedTaskStorageErrorsNeverSuppressCommand(t *testing.T) {
	for _, mode := range []string{"not-directory", "file-limit", "byte-limit", "locked"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			dir := taskSpoolDirectory(base)
			if mode == "not-directory" {
				if err := os.WriteFile(filepath.Join(base, "state"), []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "file-limit":
					for i := 0; i < maxTaskSpoolFiles; i++ {
						if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d.age", i)), []byte("existing"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				case "byte-limit":
					f, err := os.Create(filepath.Join(dir, "existing.age"))
					if err != nil {
						t.Fatal(err)
					}
					err = f.Truncate(maxTaskSpoolBytes)
					f.Close()
					if err != nil {
						t.Fatal(err)
					}
				case "locked":
					unlock, err := lockState(filepath.Join(filepath.Dir(dir), "task-spool.lock"))
					if err != nil {
						t.Fatal(err)
					}
					defer unlock()
				}
			}
			var stdout bytes.Buffer
			code, err := RunRecordedTask(context.Background(), base, "backup", recordedTaskHelper(t, "literal", "EXECUTED", "9"), &stdout, io.Discard)
			if code != 9 || err == nil || stdout.String() != "EXECUTED" {
				t.Fatalf("audit error interrupted business command: %d %v %q", code, err, stdout.String())
			}
		})
	}
}

func TestRecordedTaskValidationAndMissingExecutable(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"", "../task", "space task", strings.Repeat("a", 65)} {
		code, err := RunRecordedTask(context.Background(), base, name, recordedTaskHelper(t, "literal", "bad", "0"), io.Discard, io.Discard)
		if code != 2 || err == nil {
			t.Fatalf("invalid name accepted: %q %d %v", name, code, err)
		}
	}
	for _, args := range [][]string{nil, {"relative-command"}} {
		if code, err := RunRecordedTask(context.Background(), base, "task", args, io.Discard, io.Discard); code != 2 || err == nil {
			t.Fatalf("invalid command accepted: %v %d %v", args, code, err)
		}
	}
	if _, err := os.Stat(taskSpoolDirectory(base)); !os.IsNotExist(err) {
		t.Fatal("invalid input wrote a task event")
	}
	code, err := RunRecordedTask(context.Background(), base, "missing", []string{filepath.Join(base, "missing-executable")}, io.Discard, io.Discard)
	if code != 127 || err == nil {
		t.Fatalf("missing executable exit status: %d %v", code, err)
	}
	events := readTaskSpool(t, base)
	if len(events) != 2 || events[1].Data["kind"] != "task_failed" {
		t.Fatal("launch failure was not recorded")
	}
}

func TestRecordedTaskCancellationAndUniqueInvocations(t *testing.T) {
	base := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	code, _ := RunRecordedTask(ctx, base, "sleep", recordedTaskHelper(t, "sleep"), io.Discard, io.Discard)
	if code == 0 || ctx.Err() == nil {
		t.Fatal("cancelled process reported success")
	}
	events := readTaskSpool(t, base)
	if len(events) != 2 || events[1].Data["details"].(map[string]any)["cancelled"] != true {
		t.Fatal("cancellation was not recorded")
	}
	first := events[0].Data["invocation_id"]
	if code, err := RunRecordedTask(context.Background(), base, "sleep", recordedTaskHelper(t, "literal", "ok", "0"), io.Discard, io.Discard); code != 0 || err != nil {
		t.Fatalf("second task failed: %d %v", code, err)
	}
	events = readTaskSpool(t, base)
	if len(events) != 4 || events[2].Data["invocation_id"] == first {
		t.Fatal("task invocations reused an identity")
	}
}

type failingTaskWriter struct{}

func (failingTaskWriter) Write([]byte) (int, error) { return 0, errors.New("destination unavailable") }

func TestRecordedTaskOutputWriterErrorDoesNotChangeExitCode(t *testing.T) {
	base := t.TempDir()
	code, err := RunRecordedTask(context.Background(), base, "output", recordedTaskHelper(t, "large"), failingTaskWriter{}, io.Discard)
	if code != 0 || err == nil {
		t.Fatalf("output forwarding changed command exit code: %d %v", code, err)
	}
	if len(readTaskSpool(t, base)) != 2 {
		t.Fatal("writer failure prevented completion event")
	}
}

func TestRecordedTaskEscapedMetadataFitsTransport(t *testing.T) {
	base := t.TempDir()
	args := recordedTaskHelper(t, "literal", strings.Repeat("\x01", 2000), "0")
	if code, err := RunRecordedTask(context.Background(), base, "escaped", args, io.Discard, io.Discard); code != 0 || err != nil {
		t.Fatalf("escaped task failed: %d %v", code, err)
	}
	for _, event := range readTaskSpool(t, base) {
		data, err := json.Marshal(event.Data)
		if err != nil || len(data) > 50000 {
			t.Fatalf("record exceeds queue transport limit: %d %v", len(data), err)
		}
		if event.Data["argv_truncated"] != true {
			t.Fatal("oversize metadata was not marked truncated")
		}
	}
}
