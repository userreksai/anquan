package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const HistoryCommandLimit = 64 << 10

// JSON may escape each input byte. The command itself is still limited to 64 KiB.
const historyCommandFrameLimit = 6*HistoryCommandLimit + 256

type historyCommandRequest struct {
	Command string `json:"command"`
}

type historyCommandResponse struct {
	Version int    `json:"version"`
	Error   string `json:"error,omitempty"`
}

// HistoryCommandSocket is shared by the managed shell hook and root service.
func HistoryCommandSocket(baseDir string) string {
	if usesSystemRuntimeDirectory(baseDir) {
		baseDir = systemAgentRuntimeDirectory
	}
	return filepath.Join(baseDir, ".history-command", "agent.sock")
}

func validateHistoryCommand(command string) error {
	if len(command) > HistoryCommandLimit {
		return fmt.Errorf("command exceeds %d bytes", HistoryCommandLimit)
	}
	if !utf8.ValidString(command) || strings.IndexByte(command, 0) >= 0 {
		return fmt.Errorf("command must be valid UTF-8 without NUL bytes")
	}
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("command must not be empty")
	}
	return nil
}

func readHistoryCommandFrame(reader io.Reader) ([]byte, error) {
	data, err := bufio.NewReader(io.LimitReader(reader, historyCommandFrameLimit+1)).ReadBytes('\n')
	if len(data) > historyCommandFrameLimit {
		return nil, fmt.Errorf("command message exceeds size limit")
	}
	if err != nil {
		return nil, fmt.Errorf("incomplete command message: %w", err)
	}
	return data, nil
}

func decodeHistoryCommandFrame(data []byte, target any) error {
	if len(data) > historyCommandFrameLimit || !utf8.Valid(data) {
		return fmt.Errorf("invalid command message encoding or size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid command message: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("command message has trailing content")
	}
	return nil
}

func escapedHistoryCommand(command string) string {
	return strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(command)
}
