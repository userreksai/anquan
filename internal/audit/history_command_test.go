package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestHistoryCommandValidation(t *testing.T) {
	for _, command := range []string{"", " \t\r\n", "echo\x00bad", string([]byte{0xff}), strings.Repeat("x", HistoryCommandLimit+1)} {
		if validateHistoryCommand(command) == nil {
			t.Fatalf("invalid command accepted: %q", command[:min(len(command), 50)])
		}
	}
	for _, command := range []string{"echo hello", "printf '你好'", "one\r\ntwo", strings.Repeat("x", HistoryCommandLimit)} {
		if err := validateHistoryCommand(command); err != nil {
			t.Fatalf("valid command rejected: %v", err)
		}
	}
	if got := escapedHistoryCommand("echo one\r\necho two\n"); got != `echo one\r\necho two\n` {
		t.Fatalf("line injection not escaped: %q", got)
	}
}

func TestHistoryCommandStrictProtocol(t *testing.T) {
	for _, frame := range []string{
		`{"command":"true","user":"root"}`,
		`{"command":"true","path":"/etc/shadow"}`,
		`{"command":"true","time":"2020-01-01"}`,
		`{"command":"true"} {}`,
		string([]byte{'"', 0xff, '"'}),
	} {
		var req historyCommandRequest
		if decodeHistoryCommandFrame([]byte(frame), &req) == nil {
			t.Fatalf("untrusted protocol fields accepted: %q", frame)
		}
	}
	command := strings.Repeat("\x01", HistoryCommandLimit)
	data, err := json.Marshal(historyCommandRequest{Command: command})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	frame, err := readHistoryCommandFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("bounded JSON expansion rejected: %v", err)
	}
	var req historyCommandRequest
	if err := decodeHistoryCommandFrame(frame, &req); err != nil || req.Command != command {
		t.Fatalf("64 KiB command not preserved: %v", err)
	}
	if _, err := readHistoryCommandFrame(io.LimitReader(strings.NewReader(strings.Repeat("x", historyCommandFrameLimit+1)), historyCommandFrameLimit+1)); err == nil {
		t.Fatal("unbounded frame accepted")
	}
	if _, err := readHistoryCommandFrame(strings.NewReader(`{"command":"true"}`)); err == nil {
		t.Fatal("unterminated frame accepted")
	}
}
