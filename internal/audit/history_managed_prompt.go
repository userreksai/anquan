package audit

// Bash cannot replace readonly functions. Detect that before defining any of
// the managed functions, and report a failed source instead of a false success.
const managedHistoryPreflight = `for _audit_log_function in _audit_log _audit_log_debug _audit_log_prompt_pause _audit_log_prompt_resume; do
    _audit_log_function_decl=$(declare -p -F "$_audit_log_function" 2>/dev/null) || _audit_log_function_decl=
    if [[ $_audit_log_function_decl =~ ^declare\ -[^[:space:]]*r ]]; then
        printf '%s\n' "anquan history: ERROR: readonly function $_audit_log_function prevents the mandatory command hook; remove its readonly declaration from shell startup and reconnect" >&2
        _ANQUAN_HISTORY_INSTALL_FAILED=1
        _ANQUAN_HISTORY_READY=0
        return 1
    fi
done
unset _audit_log_function _audit_log_function_decl
`

// The managed hook owns DEBUG. Reasserting it at every prompt also supersedes
// traps installed later by a profile or by an ordinary prompt callback.
// This remains separate from the repair-only gate, which preserves foreign hooks.
const managedHistoryPromptTail = `_audit_log_prompt_status=$?
trap '_audit_log_debug' DEBUG
_audit_log_prompt_resume "$_audit_log_prompt_status"`

const managedHistoryPromptGate = `# anquan-managed-history-prompt-gate-v2
_audit_log_prompt_decl=$(declare -p PROMPT_COMMAND 2>/dev/null) || _audit_log_prompt_decl=
if [[ ${_ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED-0} == 1 && $_audit_log_prompt_decl != "${_ANQUAN_MANAGED_HISTORY_PROMPT_DECL-}" ]]; then
    _ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED=0
fi
if [[ ${_ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED-0} != 1 ]]; then
    if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*r ]]; then
        printf '%s\n' 'anquan history: ERROR: readonly PROMPT_COMMAND prevents the mandatory command hook; remove the readonly declaration from shell startup and reconnect' >&2
        _ANQUAN_HISTORY_INSTALL_FAILED=1
        _ANQUAN_HISTORY_READY=0
        return 1
    fi
    if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*[Ainlu] ]]; then
        # Remove a nameref itself without unsetting its target. Other attributes
        # can also transform the hook text, so replace those incompatible values.
        if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*n ]]; then
            unset -n PROMPT_COMMAND
        else
            unset PROMPT_COMMAND
        fi
        _audit_log_prompt_decl=
    fi
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
                _audit_log|_audit_log\ *|_audit_log_*) ;;
                *) _audit_log "$BASH_COMMAND" ;;
            esac
        fi
        return 0
    }
    _audit_log_prompt_tail=__ANQUAN_PROMPT_TAIL__
    if [[ $_audit_log_prompt_decl =~ ^declare\ -[^[:space:]]*a ]]; then
        if (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )); then
            PROMPT_COMMAND=('_audit_log_prompt_pause' "${PROMPT_COMMAND[@]}" "$_audit_log_prompt_tail")
        else
            PROMPT_COMMAND[0]=$'_audit_log_prompt_pause\n'"${PROMPT_COMMAND[0]-}"$'\n'"$_audit_log_prompt_tail"
        fi
    else
        PROMPT_COMMAND=$'_audit_log_prompt_pause\n'"${PROMPT_COMMAND-}"$'\n'"$_audit_log_prompt_tail"
    fi
    _ANQUAN_HISTORY_READY=0
    _ANQUAN_HISTORY_INSTALL_FAILED=0
    _ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED=1
    _ANQUAN_MANAGED_HISTORY_PROMPT_DECL=$(declare -p PROMPT_COMMAND)
    unset _audit_log_prompt_tail
fi
unset _audit_log_prompt_decl`
