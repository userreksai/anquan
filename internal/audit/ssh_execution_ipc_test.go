package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHExecutionSocketKeepsCustomDeploymentDirectory(t *testing.T) {
	base := t.TempDir()
	want := filepath.Join(base, ".ssh-execution", "agent.sock")
	if got := SSHExecutionSocket(base); got != want {
		t.Fatalf("socket path %q, want %q", got, want)
	}
}

func TestSSHExecutionFrameRejectsUnknownTrailingAndOversizeData(t *testing.T) {
	for _, input := range []string{
		`{"ID":"request","Connection":"test","Username":"root"}`,
		`{"ID":"request"} {"ID":"second"}`,
		strings.Repeat(" ", sshExecutionFrameLimit+1),
	} {
		var req SSHExecutionRequest
		if err := decodeSSHExecutionFrame([]byte(input), &req); err == nil {
			t.Fatalf("accepted invalid frame %q", input[:min(80, len(input))])
		}
	}
	var req SSHExecutionRequest
	if err := decodeSSHExecutionFrame([]byte("{\"ID\":\"first\",\"Connection\":\"127.0.0.1 1234 127.0.0.1 22\"}\n"), &req); err != nil || req.ID != "first" {
		t.Fatalf("valid frame rejected: %+v, %v", req, err)
	}
}
