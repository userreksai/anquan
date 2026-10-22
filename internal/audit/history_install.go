package audit

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
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
	tail := quote(managedHistoryPromptTail)
	gate := strings.ReplaceAll(managedHistoryPromptGate, "__ANQUAN_PROMPT_TAIL__", tail)
	return []byte(managedHistoryScriptMarker +
		"_audit_log_source_ready=${_ANQUAN_HISTORY_READY-0}\n" +
		"_audit_log_source_paused=$((_ANQUAN_HISTORY_READY=0))\n" +
		"if [ -z \"${BASH_VERSION-}\" ]; then return 0; fi\n" +
		"case $- in *i*) ;; *) return 0 ;; esac\n" +
		"eval " + quote(managedHistoryPreflight+writer+gate) + "\n" +
		"_audit_log_source_resumed=$((_ANQUAN_HISTORY_READY=_audit_log_source_ready))\n")
}

// ensureHistoryScriptAt converges both missing and existing hooks to the
// current Agent writer. Replacements always retain a backup of the old hook.
func ensureHistoryScriptAt(scriptPath, logPath, binaryPath string) (bool, error) {
	result, err := syncHistoryScriptAt(scriptPath, logPath, binaryPath, nil)
	return result.Changed, err
}

// Explicit paths keep installation tests away from the host's /etc and /var.
// The existing initializeHistoryScriptAt remains the repair-only entry point.
func initializeHistoryManagedAt(c Config, writer io.Writer, scriptPath, logPath, binaryPath string) error {
	return enforceHistoryManagedAt(c, writer, scriptPath, logPath, binaryPath)
}
