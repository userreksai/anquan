package audit

import (
	"bytes"
	"regexp"
	"strings"
)

var historyScriptAppend = regexp.MustCompile(`(?m)^[ \t]*\{[ \t]*flock[ \t]+-x[ \t]+200;[^\r\n]*>>[ \t]+/var/log/history\.log[^\r\n]*;[ \t]*\}[ \t]+200>>/var/log/history\.log[ \t]*\r?$`)
var historyScriptClearPrompt = regexp.MustCompile(`(?m)^[ \t]*export[ \t]+PROMPT_COMMAND=(''|"")[ \t]*\r?\n`)

// This code runs at the top level of PROMPT_COMMAND, after sourcing has
// finished. Installing DEBUG inside a function can be undone on return, and
// Bash may temporarily hide a caller's DEBUG trap while sourcing a file.
const historyPromptTail = `_audit_log_prompt_status=$?
if [[ ${_ANQUAN_HISTORY_DEBUG_ARMED-0} == 0 ]]; then
    case "$(trap -p DEBUG)" in
        ""|"trap -- '_audit_log' DEBUG")
            trap '_audit_log_debug' DEBUG
            ;;
        *)
            printf '%s\n' 'anquan history: existing DEBUG trap retained; command hook was not replaced' >&2
            ;;
    esac
    _ANQUAN_HISTORY_DEBUG_ARMED=1
fi
_audit_log_prompt_resume "$_audit_log_prompt_status"`

const historyPromptGate = `# anquan-history-prompt-gate-v1
if [ -z "${BASH_VERSION-}" ]; then
    return 0
fi
case $- in
    *i*)
        if [[ ${_ANQUAN_HISTORY_PROMPT_INSTALLED-0} != 1 ]]; then
            _audit_log_prompt_decl=$(declare -p PROMPT_COMMAND 2>/dev/null) || _audit_log_prompt_decl=
            if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*[rAni] ]]; then
                if [[ ${_ANQUAN_HISTORY_PROMPT_WARNED-0} != 1 ]]; then
                    printf '%s\n' 'anquan history: unsupported PROMPT_COMMAND attributes retained; deferred command hook was not installed' >&2
                    _ANQUAN_HISTORY_PROMPT_WARNED=1
                fi
            else
                _audit_log_prompt_pause() {
                    local _audit_log_status=$?
                    _ANQUAN_HISTORY_READY=0
                    return "$_audit_log_status"
                }
                _audit_log_prompt_resume() {
                    _ANQUAN_HISTORY_READY=1
                    return "$1"
                }
                _audit_log_debug() {
                    if [[ ${_ANQUAN_HISTORY_READY-0} == 1 && ${FUNCNAME[1]-} != _audit_log* ]]; then
                        case "$BASH_COMMAND" in
                            *"_audit_log"*) ;;
                            *) _audit_log ;;
                        esac
                    fi
                    return 0
                }
                _audit_log_prompt_tail=__ANQUAN_PROMPT_TAIL__
                if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*a ]]; then
                    if (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )); then
                        PROMPT_COMMAND=('_audit_log_prompt_pause' "${PROMPT_COMMAND[@]}" "$_audit_log_prompt_tail")
                    else
                        # Before Bash 5.1 only element zero is executed.
                        PROMPT_COMMAND[0]=$'_audit_log_prompt_pause\n'"${PROMPT_COMMAND[0]-}"$'\n'"$_audit_log_prompt_tail"
                    fi
                else
                    PROMPT_COMMAND=$'_audit_log_prompt_pause\n'"${PROMPT_COMMAND-}"$'\n'"$_audit_log_prompt_tail"
                fi
                _ANQUAN_HISTORY_READY=0
                _ANQUAN_HISTORY_DEBUG_ARMED=0
                _ANQUAN_HISTORY_PROMPT_INSTALLED=1
                unset _audit_log_prompt_tail
            fi
            unset _audit_log_prompt_decl
        fi
        ;;
    *)
        # Preserve the known writer's existing non-interactive behavior.
        trap '_audit_log' DEBUG
        ;;
esac`

func patchHistoryPromptScript(original []byte) ([]byte, bool) {
	if len(original) > maxHistoryScriptBytes || bytes.IndexByte(original, 0) >= 0 ||
		bytes.Contains(original, []byte("# anquan-history-prompt-gate-v1")) ||
		!historyScriptFunction.Match(original) || !historyScriptAppend.Match(original) ||
		len(historyScriptTrap.FindAllIndex(original, -1)) != 1 {
		return original, false
	}
	// Preserve custom prompt hooks. Remove only the known legacy assignment
	// which otherwise erases hooks established earlier in the login profile.
	updated := historyScriptClearPrompt.ReplaceAll(original, nil)
	quotedTail := "'" + strings.ReplaceAll(historyPromptTail, "'", "'\"'\"'") + "'"
	gate := strings.ReplaceAll(historyPromptGate, "__ANQUAN_PROMPT_TAIL__", quotedTail)
	if bytes.Contains(original, []byte("\r\n")) {
		gate = strings.ReplaceAll(gate, "\n", "\r\n")
	}
	// Use a function replacement: shell variable dollar signs are literal.
	updated = historyScriptTrap.ReplaceAllFunc(updated, func(line []byte) []byte {
		if bytes.HasSuffix(line, []byte("\r")) {
			return []byte(gate + "\r")
		}
		return []byte(gate)
	})
	return updated, true
}
