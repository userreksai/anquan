package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

// ErrSSHExecutionUnavailable permits a root caller to report directly only
// when no local service accepted the request. Business and protocol errors
// deliberately do not wrap this value, since retrying those could notify twice.
var ErrSSHExecutionUnavailable = errors.New("SSH execution service is unavailable")

const sshExecutionFrameLimit = 4096

// SSHExecutionSocket is shared by the installed client and its root service.
// The separate root-owned directory prevents users replacing the socket.
func SSHExecutionSocket(baseDir string) string {
	return filepath.Join(baseDir, ".ssh-execution", "agent.sock")
}

type sshExecutionResponse struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Error   string `json:"error,omitempty"`
}

func decodeSSHExecutionFrame(data []byte, value any) error {
	if len(data) > sshExecutionFrameLimit {
		return fmt.Errorf("SSH execution request exceeds %d bytes", sshExecutionFrameLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid SSH execution message: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("SSH execution message has trailing content")
	}
	return nil
}
