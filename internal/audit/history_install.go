package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const historyCommandBinaryPath = "/usr/local/anquan/anquan"
const managedHistoryScriptMarker = "# anquan-managed-history-v1\n"

func isManagedHistoryScript(path string) bool {
	content, _, err := readHistoryScript(path)
	return err == nil && bytes.HasPrefix(content, []byte(managedHistoryScriptMarker))
}

// The outer script is POSIX syntax, so /etc/profile.d can safely source it
// from other shells. Only interactive Bash evaluates the constant Bash body.
// All command bytes are sent on stdin, never parsed as shell code or arguments.
func managedHistoryScript(binaryPath string) []byte {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	writer := `_audit_log() {
    [ "$#" -gt 0 ] || return 0
    [ -S __ANQUAN_COMMAND_SOCKET__ ] || return 0
    { printf '%s' "$1" | __ANQUAN_COMMAND_BINARY__ -record-command; } >/dev/null 2>&1 || :
    return 0
}
`
	writer = strings.ReplaceAll(writer, "__ANQUAN_COMMAND_SOCKET__", quote(HistoryCommandSocket(filepath.Dir(binaryPath))))
	writer = strings.ReplaceAll(writer, "__ANQUAN_COMMAND_BINARY__", quote(binaryPath))
	tail := quote(historyPromptTail)
	gate := strings.ReplaceAll(historyPromptGate, "__ANQUAN_PROMPT_TAIL__", tail)
	gate = strings.Replace(gate, `*"_audit_log"*) ;;`, `_audit_log|_audit_log\ *|_audit_log_*) ;;`, 1)
	gate = strings.Replace(gate, `*) _audit_log ;;`, `*) _audit_log "$BASH_COMMAND" ;;`, 1)
	return []byte(managedHistoryScriptMarker +
		"_audit_log_source_ready=${_ANQUAN_HISTORY_READY-0}\n" +
		"_audit_log_source_paused=$((_ANQUAN_HISTORY_READY=0))\n" +
		"if [ -z \"${BASH_VERSION-}\" ]; then return 0; fi\n" +
		"case $- in *i*) ;; *) return 0 ;; esac\n" +
		"eval " + quote(writer+gate) + "\n" +
		"_audit_log_source_resumed=$((_ANQUAN_HISTORY_READY=_audit_log_source_ready))\n")
}

// ensureHistoryScriptAt installs only a missing script. In particular, an
// administrator's custom writer is never converted to the managed writer.
// A fully synced temporary inode is linked into place without replacement;
// neither a competing creator nor readers can observe a partial script.
func ensureHistoryScriptAt(scriptPath, logPath, binaryPath string) (bool, error) {
	if err := verifyHistoryManagedParents(scriptPath); err != nil {
		return false, err
	}
	if content, _, err := readHistoryScript(scriptPath); err == nil {
		if bytes.HasPrefix(content, []byte(managedHistoryScriptMarker)) {
			_, err = ensureHistoryCommandLog(logPath)
			return false, err
		}
		// An external writer retains its own log permissions and lifecycle.
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := ensureHistoryCommandLog(logPath); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(filepath.Dir(scriptPath), ".anquan-history-install-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0644); err != nil {
		return false, err
	}
	if _, err := f.Write(managedHistoryScript(binaryPath)); err != nil {
		return false, err
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := verifyHistoryManagedParents(scriptPath); err != nil {
		return false, err
	}
	if err := os.Link(f.Name(), scriptPath); os.IsExist(err) {
		_, _, readErr := readHistoryScript(scriptPath)
		return false, readErr
	} else if err != nil {
		return false, fmt.Errorf("install history audit script without replacement: %w", err)
	}
	if runtime.GOOS == "linux" {
		dir, err := os.Open(filepath.Dir(scriptPath))
		if err != nil {
			return false, err
		}
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Explicit paths keep installation tests away from the host's /etc and /var.
// The existing initializeHistoryScriptAt remains the repair-only entry point.
func initializeHistoryManagedAt(c Config, writer io.Writer, scriptPath, logPath, binaryPath string) error {
	if c.History == nil || !c.History.Enabled {
		return nil
	}
	installed, err := ensureHistoryScriptAt(scriptPath, logPath, binaryPath)
	if err != nil {
		return fmt.Errorf("history script installation failed: %w", err)
	}
	if err := initializeHistoryScriptAt(c, writer, scriptPath); err != nil {
		return err
	}
	if installed {
		return writeLog(c, writer, time.Now(), "history_script_installed", map[string]string{
			"path":    scriptPath,
			"message": "installed the managed command hook; existing interactive shells must reconnect to load it",
		})
	}
	return nil
}
