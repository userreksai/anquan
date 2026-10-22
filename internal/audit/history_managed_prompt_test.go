package audit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Run the exact managed gate with a builtin writer. This also runs in Git Bash
// on Windows, where the Linux production Unix socket fixture is unavailable.
func TestManagedHistoryPromptGateWithRealBash(t *testing.T) {
	var bash string
	for _, candidate := range []string{"bash", "sh"} {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		if err := exec.Command(path, "-c", `test -n "${BASH_VERSION-}"`).Run(); err == nil {
			bash = path
			break
		}
	}
	if bash == "" {
		t.Skip("managed prompt regression requires Bash (Git Bash is supported)")
	}
	const foreign = `trap 'printf "%s\n" "$BASH_COMMAND" >> "$_fixture_foreign"' DEBUG`
	const prompt = `PROMPT_COMMAND='printf "prompt\n" >> "$_fixture_prompts"'`
	for _, tc := range []struct {
		name, before, after string
		readonly            bool
		failureText         string
		production          bool
	}{
		{name: "empty"},
		{name: "production-no-socket", production: true},
		{name: "foreign-before", before: foreign},
		{name: "foreign-after", after: foreign},
		{name: "foreign-prompt", before: "PROMPT_COMMAND=" + managedPromptTestQuote(foreign)},
		{name: "string-prompt", before: prompt},
		{name: "array-prompt", before: `PROMPT_COMMAND=('printf "prompt\n" >> "$_fixture_prompts"')`},
		{name: "replaced-prompt", after: prompt + `; . "$_fixture_audit"`},
		{name: "associative", before: `declare -A PROMPT_COMMAND=([hook]=':')`},
		{name: "integer", before: `declare -i PROMPT_COMMAND=23`},
		{name: "nameref", before: `_fixture_target='keep'; declare -n PROMPT_COMMAND=_fixture_target`},
		{name: "lowercase", before: `declare -l PROMPT_COMMAND=':'`},
		{name: "uppercase", before: `declare -u PROMPT_COMMAND=':'`},
		{name: "readonly", before: `readonly PROMPT_COMMAND=':'`, readonly: true, production: true, failureText: "ERROR: readonly PROMPT_COMMAND prevents the mandatory command hook"},
		{name: "readonly-writer", before: `_audit_log() { :; }; readonly -f _audit_log`, readonly: true, production: true, failureText: "ERROR: readonly function _audit_log prevents the mandatory command hook"},
		{name: "readonly-debug", before: `_audit_log_debug() { :; }; readonly -f _audit_log_debug`, readonly: true, production: true, failureText: "ERROR: readonly function _audit_log_debug prevents the mandatory command hook"},
		{name: "functrace", before: "set -T"},
		{name: "extdebug", before: "shopt -s extdebug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := func(name string) string { return filepath.ToSlash(filepath.Join(dir, name)) }
			quotePath := func(name string) string { return managedPromptTestQuote(path(name)) }
			write := func(name, value string) {
				t.Helper()
				if err := os.WriteFile(path(name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Match managedHistoryScript's pause/resume around source, with a
			// builtin recorder so no host log, socket, or helper is accessed.
			script := `_audit_log_source_ready=${_ANQUAN_HISTORY_READY-0}
_audit_log_source_paused=$((_ANQUAN_HISTORY_READY=0))
` + managedHistoryPreflight + `_audit_log() { [ "$#" -gt 0 ] || return 0; printf '%s\0' "$1" >> "$_fixture_commands"; return 0; }
` + strings.ReplaceAll(managedHistoryPromptGate, "__ANQUAN_PROMPT_TAIL__", managedPromptTestQuote(managedHistoryPromptTail)) + `
_audit_log_source_resumed=$((_ANQUAN_HISTORY_READY=_audit_log_source_ready))
`
			if tc.production {
				script = string(managedHistoryScript(path("missing helper")))
			}
			write("audit.sh", script)
			write("rcfile", fmt.Sprintf(`PS1='managed-test> '
PS2=''
_fixture_commands=%s
_fixture_trace=%s
_fixture_foreign=%s
_fixture_prompts=%s
_fixture_audit=%s
%s
. "$_fixture_audit"
_fixture_source_status=$?
printf 'source-status:%%s installed:%%s failed:%%s\n' "$_fixture_source_status" "${_ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED-0}" "${_ANQUAN_HISTORY_INSTALL_FAILED-0}" >> "$_fixture_trace"
%s
printf 'startup\n' >> "$_fixture_trace"
:
`, quotePath("commands"), quotePath("trace"), quotePath("foreign"), quotePath("prompts"), quotePath("audit.sh"), tc.before, tc.after))
			const status = `printf 'status:%s\n' "$?" >> "$_fixture_trace"`
			const source = `source "$_fixture_audit"`
			input := strings.Join([]string{"false", status, source, "true", "exit 0", ""}, "\n")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "--noprofile", "--rcfile", path("rcfile"), "-i")
			cmd.WaitDelay = time.Second
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				switch key {
				case "HOME", "BASH_ENV", "ENV", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "PS0", "PS1", "PS2", "LC_ALL", "TERM":
				default:
					if !strings.HasPrefix(key, "BASH_FUNC_") {
						cmd.Env = append(cmd.Env, entry)
					}
				}
			}
			// Bash invoked as sh ignores --rcfile, but reads ENV for an
			// interactive shell. A normal Bash invocation uses --rcfile.
			cmd.Env = append(cmd.Env, "HOME="+path("."), "LC_ALL=C", "TERM=dumb", "ENV="+path("rcfile"))
			cmd.Stdin = strings.NewReader(input)
			output, err := cmd.CombinedOutput()
			if err != nil || ctx.Err() != nil {
				t.Fatalf("managed Bash gate failed: %v / %v\n%s", err, ctx.Err(), output)
			}
			read := func(name string) string {
				t.Helper()
				value, err := os.ReadFile(path(name))
				if os.IsNotExist(err) {
					return ""
				}
				if err != nil {
					t.Fatal(err)
				}
				return string(value)
			}
			commands := strings.Split(strings.TrimSuffix(read("commands"), "\x00"), "\x00")
			if tc.readonly {
				if read("commands") != "" || !strings.Contains(read("trace"), "source-status:1 installed:0 failed:1\n") ||
					!strings.Contains(string(output), tc.failureText) {
					t.Fatalf("readonly failure was hidden: commands %q trace %q\n%s", commands, read("trace"), output)
				}
				return
			}
			if tc.production {
				if read("commands") != "" || !strings.Contains(read("trace"), "source-status:0 installed:1 failed:0\nstartup\nstatus:1\n") {
					t.Fatalf("offline production hook changed source/command status: %q\n%s", read("trace"), output)
				}
				return
			}
			for _, command := range []string{"false", status, source, "true", "exit 0"} {
				count := 0
				for _, recorded := range commands {
					if recorded == command {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("command %q recorded %d times: %q\n%s", command, count, commands, output)
				}
			}
			if !strings.Contains(read("trace"), "source-status:0 installed:1 failed:0\nstartup\nstatus:1\n") {
				t.Fatalf("source or command status changed: %q\n%s", read("trace"), output)
			}
			if slices.Contains(strings.Split(read("foreign"), "\n"), "true") {
				t.Fatalf("foreign DEBUG trap still owns user commands: %q\n%s", read("foreign"), output)
			}
			for _, command := range commands {
				if strings.Contains(command, "startup") || strings.HasPrefix(command, "_audit_log") {
					t.Fatalf("startup or hook internals recorded: %q\n%s", commands, output)
				}
			}
			if (tc.name == "string-prompt" || tc.name == "array-prompt" || tc.name == "replaced-prompt") && read("prompts") != strings.Repeat("prompt\n", 5) {
				t.Fatalf("re-sourcing stacked ordinary prompt callbacks: %q\n%s", read("prompts"), output)
			}
		})
	}
}

func managedPromptTestQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
