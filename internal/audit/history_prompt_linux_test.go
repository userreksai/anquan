//go:build linux

package audit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type historyPromptBashResult struct {
	commands []string
	trace    []string
	prompts  []string
	foreign  []string
	output   string
}

func historyPromptShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Run a real interactive Bash without loading the host's profile. Everything
// the audit writer and fixture hooks produce is confined to this test directory.
func runHistoryPromptBash(t *testing.T, beforeSource, afterSource, input string) historyPromptBashResult {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("interactive Bash regression requires bash")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("interactive Bash regression requires flock")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	auditPath := filepath.Join(dir, "audit.sh")
	tracePath := filepath.Join(dir, "execution.log")
	promptPath := filepath.Join(dir, "prompts.log")
	foreignPath := filepath.Join(dir, "foreign.log")
	sourcePath := filepath.Join(dir, "user-source.sh")
	profileDir := filepath.Join(dir, "profile.d")
	if err := os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	patched, changed := patchHistoryPromptScript([]byte(fixedHistoryScript()))
	if !changed {
		t.Fatal("known append writer did not receive the deferred prompt hook")
	}
	write(auditPath, strings.ReplaceAll(string(patched), "/var/log/history.log", historyPromptShellQuote(logPath)))
	write(filepath.Join(profileDir, "fixture.sh"), "printf '%s\\n' profile-ran >> \"$_fixture_trace\"\n")
	write(sourcePath, "printf '%s\\n' sourced-ran >> \"$_fixture_trace\"\n")
	// Fixed timestamps exercise multiple occurrences in the same second. These
	// functions also avoid depending on a controlling tty or the runner's user.
	rc := fmt.Sprintf(`PS1='fixture> '
PS2=''
whoami() { printf 'fixture-user\n'; }
tty() { printf '/dev/pts/test\n'; }
date() { printf '2026-10-19 08:00:00\n'; }
_fixture_log=%s
_fixture_trace=%s
_fixture_prompts=%s
_fixture_foreign=%s
_fixture_audit=%s
_fixture_source=%s
_fixture_check_log() { grep -Fq -- "$1" "$_fixture_log" || exit 91; }
_fixture_user_function() { printf '%%s\n' function-ran >> "$_fixture_trace"; return 0; }
%s
. "$_fixture_audit"
for i in %s/*.sh; do
    [ -r "$i" ] && . "$i"
done
%s
:
`, historyPromptShellQuote(logPath), historyPromptShellQuote(tracePath), historyPromptShellQuote(promptPath), historyPromptShellQuote(foreignPath), historyPromptShellQuote(auditPath), historyPromptShellQuote(sourcePath), beforeSource, historyPromptShellQuote(profileDir), afterSource)
	rcPath := filepath.Join(dir, "rcfile")
	write(rcPath, rc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--rcfile", rcPath, "-i")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	// Do not inherit shell startup hooks or tracing options from the CI worker.
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
	cmd.Env = append(cmd.Env, "HOME="+dir, "LC_ALL=C", "TERM=dumb")
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("interactive Bash did not finish: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("interactive Bash failed: %v\n%s", err, output)
	}
	readLines := func(path string) []string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		text := strings.TrimSuffix(string(raw), "\n")
		if text == "" {
			return nil
		}
		return strings.Split(text, "\n")
	}
	result := historyPromptBashResult{trace: readLines(tracePath), prompts: readLines(promptPath), foreign: readLines(foreignPath), output: string(output)}
	for i, line := range readLines(logPath) {
		record, err := parseHistoryLine(line, logPath, "fixture", int64(i), time.UTC)
		if err != nil {
			t.Fatalf("invalid audit output %q: %v\n%s", line, err, output)
		}
		result.commands = append(result.commands, record.Command)
	}
	return result
}

func requireHistoryPromptCommandCount(t *testing.T, result historyPromptBashResult, command string, want int) {
	t.Helper()
	count := 0
	for _, recorded := range result.commands {
		if recorded == command {
			count++
		}
	}
	if count != want {
		t.Fatalf("command %q recorded %d times, want %d\ncommands: %q\nshell output:\n%s", command, count, want, result.commands, result.output)
	}
}

func TestHistoryPromptBashDefersProfileAndRecordsInteractiveOccurrences(t *testing.T) {
	const ordinary = `printf '%s\n' ordinary >> "$_fixture_trace"`
	const repeated = `printf '%s\n' same-second >> "$_fixture_trace"`
	const sourced = `source "$_fixture_source"`
	for _, termination := range []string{"exit 0", "exec true"} {
		t.Run(termination, func(t *testing.T) {
			input := strings.Join([]string{ordinary, repeated, repeated, sourced, `_fixture_check_log same-second`, termination, ""}, "\n")
			result := runHistoryPromptBash(t, "", "", input)
			if want := []string{"profile-ran", "ordinary", "same-second", "same-second", "sourced-ran"}; !slices.Equal(result.trace, want) {
				t.Fatalf("interactive commands did not execute in order: got %q, want %q\n%s", result.trace, want, result.output)
			}
			for _, command := range []string{ordinary, sourced, termination} {
				requireHistoryPromptCommandCount(t, result, command, 1)
			}
			requireHistoryPromptCommandCount(t, result, repeated, 2)
			for _, command := range result.commands {
				if strings.Contains(command, `for i in `) || strings.Contains(command, `[ -r "$i" ]`) || strings.Contains(command, `. "$i"`) || strings.Contains(command, "profile-ran") {
					t.Fatalf("profile initialization leaked into the command log: %q", command)
				}
			}
		})
	}
}

func TestHistoryPromptBashPreservesStringAndArrayHooksAndStatus(t *testing.T) {
	const functions = `_fixture_first() { local previous=$?; printf 'first:%s\n' "$previous" >> "$_fixture_prompts"; return 23; }
_fixture_second() { local previous=$?; printf 'second:%s\n' "$previous" >> "$_fixture_prompts"; return 29; }
`
	for _, tc := range []struct{ name, prompt string }{
		{"string-with-tail-comment", `PROMPT_COMMAND='_fixture_first; _fixture_second # retained tail comment'`},
		{"array-with-tail-comments", `PROMPT_COMMAND=('_fixture_first # retained first comment' '_fixture_second # retained second comment')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const input = "false\ntrue\nexit 0\n"
			// Reset the original prompt after sourcing for the control shell,
			// before the deferred DEBUG trap is armed. Compare with Bash's own
			// unwrapped string/array semantics rather than assuming the two
			// PROMPT_COMMAND representations propagate statuses identically.
			baseline := runHistoryPromptBash(t, functions+tc.prompt, tc.prompt, input)
			result := runHistoryPromptBash(t, functions+tc.prompt, "", input)
			if len(baseline.prompts) != 6 || !slices.Equal(result.prompts, baseline.prompts) {
				t.Fatalf("prompt hooks lost order or incoming status: got %q, original %q\n%s", result.prompts, baseline.prompts, result.output)
			}
			for _, command := range []string{"false", "true", "exit 0"} {
				requireHistoryPromptCommandCount(t, result, command, 1)
			}
			for _, command := range result.commands {
				if strings.Contains(command, "_fixture_first") || strings.Contains(command, "_fixture_second") {
					t.Fatalf("prompt hook was logged as a user command: %q", command)
				}
			}
		})
	}
}

func TestHistoryPromptBashResourcingDoesNotStackHooks(t *testing.T) {
	before := `_fixture_record_prompt() { printf '%s\n' prompt >> "$_fixture_prompts"; }
PROMPT_COMMAND=_fixture_record_prompt`
	const command = `printf '%s\n' after-source >> "$_fixture_trace"`
	result := runHistoryPromptBash(t, before, "", "source \"$_fixture_audit\"\n"+command+"\nexit 0\n")
	if want := []string{"prompt", "prompt", "prompt"}; !slices.Equal(result.prompts, want) {
		t.Fatalf("re-sourcing stacked prompt hooks: got %q, want %q\n%s", result.prompts, want, result.output)
	}
	requireHistoryPromptCommandCount(t, result, `source "$_fixture_audit"`, 1)
	requireHistoryPromptCommandCount(t, result, command, 1)
	requireHistoryPromptCommandCount(t, result, "exit 0", 1)
}

func TestHistoryPromptBashPreservesForeignDebugTrap(t *testing.T) {
	const trap = `trap 'printf "%s\n" "$BASH_COMMAND" >> "$_fixture_foreign"' DEBUG`
	const command = `printf '%s\n' foreign-command >> "$_fixture_trace"`
	for _, tc := range []struct{ name, before, after string }{
		{"before-source", trap, ""},
		{"after-source-before-first-prompt", "", trap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runHistoryPromptBash(t, tc.before, tc.after, command+"\nexit 0\n")
			if !slices.Contains(result.foreign, command) || !slices.Contains(result.foreign, "exit 0") {
				t.Fatalf("foreign DEBUG trap was replaced: trace %q\n%s", result.foreign, result.output)
			}
			if len(result.commands) != 0 {
				t.Fatalf("deferred hook replaced the foreign trap: %q", result.commands)
			}
			if !strings.Contains(result.output, "existing DEBUG trap retained") {
				t.Fatalf("foreign trap retention was not explained: %s", result.output)
			}
		})
	}
}

func TestHistoryPromptBashReadonlyPromptDoesNotBreakShell(t *testing.T) {
	before := `_fixture_record_prompt() { printf '%s\n' readonly-prompt >> "$_fixture_prompts"; }
readonly PROMPT_COMMAND=_fixture_record_prompt`
	const command = `printf '%s\n' readonly-command >> "$_fixture_trace"`
	result := runHistoryPromptBash(t, before, "", command+"\nexit 0\n")
	if want := []string{"profile-ran", "readonly-command"}; !slices.Equal(result.trace, want) {
		t.Fatalf("readonly prompt stopped shell execution: %q\n%s", result.trace, result.output)
	}
	if want := []string{"readonly-prompt", "readonly-prompt"}; !slices.Equal(result.prompts, want) {
		t.Fatalf("readonly prompt hook was lost: %q\n%s", result.prompts, result.output)
	}
	if len(result.commands) != 0 || !strings.Contains(result.output, "unsupported PROMPT_COMMAND attributes retained") {
		t.Fatalf("readonly prompt was not safely retained: commands %q\n%s", result.commands, result.output)
	}
}

func TestHistoryPromptBashTracingDoesNotSkipCommands(t *testing.T) {
	for _, tc := range []struct{ name, setup string }{
		{"functrace", "set -T"},
		{"extdebug", "shopt -s extdebug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const first = `printf '%s\n' first >> "$_fixture_trace"`
			const last = `printf '%s\n' last >> "$_fixture_trace"`
			input := first + "\nfalse\nprintf 'status:%s\\n' \"$?\" >> \"$_fixture_trace\"\n_fixture_user_function\n" + last + "\nexit 0\n"
			result := runHistoryPromptBash(t, tc.setup, "", input)
			if want := []string{"profile-ran", "first", "status:1", "function-ran", "last"}; !slices.Equal(result.trace, want) {
				t.Fatalf("tracing skipped commands or changed status: got %q, want %q\n%s", result.trace, want, result.output)
			}
			requireHistoryPromptCommandCount(t, result, first, 1)
			requireHistoryPromptCommandCount(t, result, last, 1)
			requireHistoryPromptCommandCount(t, result, "exit 0", 1)
		})
	}
}
