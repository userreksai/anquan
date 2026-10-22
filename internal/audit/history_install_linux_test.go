//go:build linux

package audit

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the installed script with real interactive Bash and a fake recorder.
// No host profiles, root configuration, command log or Agent socket are used.
func runManagedHistoryBash(t *testing.T, before, after, input string, helperExit int, socketPresent bool) historyPromptBashResult {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("interactive Bash regression requires bash")
	}
	// Unix socket paths are limited to roughly 108 bytes; t.TempDir includes
	// the (long) test name and can exceed that limit before the socket suffix.
	dir, err := os.MkdirTemp("", "anquan-hsh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	binary := filepath.Join(dir, "agent with spaces")
	commandPath := filepath.Join(dir, "commands")
	promptsPath := filepath.Join(dir, "prompts")
	tracePath := filepath.Join(dir, "trace")
	foreignPath := filepath.Join(dir, "foreign")
	script := filepath.Join(dir, "history-audit.sh")
	write := func(path, value string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(script, string(managedHistoryScript(binary)), 0600)
	write(binary, fmt.Sprintf("#!/bin/sh\n[ \"$1\" = -record-command ] || exit 89\ncat >> %s\nprintf '\\0' >> %s\nexit %d\n", historyPromptShellQuote(commandPath), historyPromptShellQuote(commandPath), helperExit), 0700)
	if socketPresent {
		socketPath := HistoryCommandSocket(filepath.Dir(binary))
		if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
	}
	rc := fmt.Sprintf(`PS1='managed> '
PS2=''
_fixture_trace=%s
_fixture_prompts=%s
_fixture_foreign=%s
_fixture_audit=%s
%s
. "$_fixture_audit"
_fixture_source_status=$?
printf '%%s\n' profile-ran >> "$_fixture_trace"
%s
:
`, historyPromptShellQuote(tracePath), historyPromptShellQuote(promptsPath), historyPromptShellQuote(foreignPath), historyPromptShellQuote(script), before, after)
	rcPath := filepath.Join(dir, "rcfile")
	write(rcPath, rc, 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--rcfile", rcPath, "-i")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
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
	if ctx.Err() != nil || err != nil {
		t.Fatalf("managed interactive Bash failed: %v %v\n%s", ctx.Err(), err, output)
	}
	read := func(path, separator string) []string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			return nil
		}
		return strings.Split(strings.TrimSuffix(string(raw), separator), separator)
	}
	return historyPromptBashResult{
		commands: read(commandPath, "\x00"), prompts: read(promptsPath, "\n"),
		trace: read(tracePath, "\n"), foreign: read(foreignPath, "\n"), output: string(output),
	}
}

func TestManagedHistoryBashRecordsCommandsWithoutStartupOrKeywordFiltering(t *testing.T) {
	const repeated = `printf '%s\n' repeat >> "$_fixture_trace"`
	const keywords = `printf '%s\n' 'history tty whoami _audit_log' >> "$_fixture_trace"`
	const multiline = "printf '%s\\n' 'first\nsecond' >> \"$_fixture_trace\""
	const loop = `for item in a b; do printf '%s\n' "$item" >> "$_fixture_trace"; done`
	input := strings.Join([]string{repeated, repeated, keywords, multiline, loop, `source "$_fixture_audit"`, repeated, "exit 0", ""}, "\n")
	result := runManagedHistoryBash(t, "", "", input, 0, true)
	for _, command := range []string{keywords, multiline, `source "$_fixture_audit"`, "exit 0"} {
		requireHistoryPromptCommandCount(t, result, command, 1)
	}
	requireHistoryPromptCommandCount(t, result, repeated, 3)
	if !slices.Equal(result.trace, []string{"profile-ran", "repeat", "repeat", "history tty whoami _audit_log", "first", "second", "a", "b", "repeat"}) {
		t.Fatalf("script changed shell commands: %q\n%s", result.trace, result.output)
	}
	for _, command := range result.commands {
		if strings.Contains(command, "profile-ran") || strings.HasPrefix(command, "_audit_log") {
			t.Fatalf("startup or recorder internals were logged: %q", command)
		}
	}
}

func TestManagedHistoryBashPreservesPromptHooksAndFailureStatus(t *testing.T) {
	const functions = `_fixture_first() { local previous=$?; printf 'first:%s\n' "$previous" >> "$_fixture_prompts"; return 23; }
_fixture_second() { local previous=$?; printf 'second:%s\n' "$previous" >> "$_fixture_prompts"; return 29; }
`
	for _, prompt := range []string{
		`PROMPT_COMMAND='_fixture_first; _fixture_second # keep'`,
		`PROMPT_COMMAND=('_fixture_first # keep' '_fixture_second # keep')`,
	} {
		input := "false\nprintf 'status:%s\\n' \"$?\" >> \"$_fixture_trace\"\nexit 0\n"
		baseline := runManagedHistoryBash(t, functions+prompt, prompt, input, 0, true)
		result := runManagedHistoryBash(t, functions+prompt, "", input, 7, true)
		if !slices.Equal(result.prompts, baseline.prompts) || !slices.Equal(result.trace, []string{"profile-ran", "status:1"}) {
			t.Fatalf("helper failure changed prompt or status: %q / %q baseline %q\n%s", result.prompts, result.trace, baseline.prompts, result.output)
		}
		requireHistoryPromptCommandCount(t, result, "false", 1)
		requireHistoryPromptCommandCount(t, result, "exit 0", 1)
	}
}

func TestManagedHistoryBashReplacesForeignDebugTraps(t *testing.T) {
	const foreign = `trap 'printf "%s\n" "$BASH_COMMAND" >> "$_fixture_foreign"' DEBUG`
	for _, tc := range []struct{ name, before, after string }{
		{"foreign-before", foreign, ""}, {"foreign-after", "", foreign},
		{"prompt-callback", "PROMPT_COMMAND=" + historyPromptShellQuote(foreign), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runManagedHistoryBash(t, tc.before, tc.after, "true\nexit 0\n", 0, true)
			for _, command := range []string{"true", "exit 0"} {
				requireHistoryPromptCommandCount(t, result, command, 1)
				if slices.Contains(result.foreign, command) {
					t.Fatalf("foreign DEBUG trap still owns user commands: %q\n%s", result.foreign, result.output)
				}
			}
		})
	}
}

func TestManagedHistoryBashNormalizesIncompatiblePromptAttributes(t *testing.T) {
	for _, setup := range []string{
		`declare -A PROMPT_COMMAND=([hook]=':')`,
		`declare -i PROMPT_COMMAND=23`,
		`_fixture_original_prompt=':'; declare -n PROMPT_COMMAND=_fixture_original_prompt`,
		`declare -l PROMPT_COMMAND=':'`,
		`declare -u PROMPT_COMMAND=':'`,
	} {
		t.Run(setup, func(t *testing.T) {
			result := runManagedHistoryBash(t, setup, "", "false\nprintf 'status:%s\\n' \"$?\" >> \"$_fixture_trace\"\nexit 0\n", 0, true)
			if !slices.Equal(result.trace, []string{"profile-ran", "status:1"}) {
				t.Fatalf("prompt normalization changed command status: %q\n%s", result.trace, result.output)
			}
			for _, command := range []string{"false", "exit 0"} {
				requireHistoryPromptCommandCount(t, result, command, 1)
			}
		})
	}
}

func TestManagedHistoryBashReportsReadonlyPromptFailure(t *testing.T) {
	const after = `printf 'source-status:%s installed:%s failed:%s\n' "$_fixture_source_status" "${_ANQUAN_MANAGED_HISTORY_PROMPT_INSTALLED-0}" "${_ANQUAN_HISTORY_INSTALL_FAILED-0}" >> "$_fixture_trace"`
	result := runManagedHistoryBash(t, `readonly PROMPT_COMMAND=':'`, after, "true\nexit 0\n", 0, true)
	if len(result.commands) != 0 || !strings.Contains(result.output, "ERROR: readonly PROMPT_COMMAND prevents the mandatory command hook") ||
		!slices.Equal(result.trace, []string{"profile-ran", "source-status:1 installed:0 failed:1"}) {
		t.Fatalf("readonly prompt failure was not explicit: commands %q trace %q\n%s", result.commands, result.trace, result.output)
	}
}

func TestManagedHistoryBashDoesNotSpawnRecorderWithoutSocket(t *testing.T) {
	result := runManagedHistoryBash(t, "", "", "false\nprintf 'status:%s\\n' \"$?\" >> \"$_fixture_trace\"\nexit 0\n", 0, false)
	if len(result.commands) != 0 || !slices.Equal(result.trace, []string{"profile-ran", "status:1"}) {
		t.Fatalf("offline recorder ran or changed command status: %q %q\n%s", result.commands, result.trace, result.output)
	}
}

func TestManagedHistoryBashPreservesTracingAndErrexitWithFailedClient(t *testing.T) {
	for _, setup := range []string{"set -T", "shopt -s extdebug", "set -e", "set -e -o pipefail"} {
		t.Run(setup, func(t *testing.T) {
			const command = `printf '%s\n' after-source >> "$_fixture_trace"`
			input := `source "$_fixture_audit"` + "\n" + command + "\ntrue\nexit 0\n"
			result := runManagedHistoryBash(t, setup, "", input, 7, true)
			if !slices.Equal(result.trace, []string{"profile-ran", "after-source"}) {
				t.Fatalf("failed recorder or tracing interrupted commands: %q\n%s", result.trace, result.output)
			}
			for _, expected := range []string{`source "$_fixture_audit"`, command, "true", "exit 0"} {
				requireHistoryPromptCommandCount(t, result, expected, 1)
			}
			for _, recorded := range result.commands {
				if strings.Contains(recorded, "anquan-managed-history") || strings.Contains(recorded, "eval ") || strings.Contains(recorded, "profile-ran") {
					t.Fatalf("source internals were recorded: %q\n%s", recorded, result.output)
				}
			}
		})
	}
}

func TestManagedHistoryScriptOtherShellAndNoninteractive(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "history.sh")
	if err := os.WriteFile(script, managedHistoryScript(filepath.Join(dir, "nonexistent helper")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		shell string
		args  []string
	}{
		{"sh", []string{"-n", script}},
		{"sh", []string{"-c", `. "$1"; printf preserved`, "fixture", script}},
		{"bash", []string{"--noprofile", "--norc", "-c", `. "$1"; trap -p DEBUG; printf preserved`, "fixture", script}},
	} {
		path, err := exec.LookPath(tc.shell)
		if err != nil {
			t.Skipf("%s unavailable", tc.shell)
		}
		out, err := exec.Command(path, tc.args...).CombinedOutput()
		if err != nil || (tc.args[0] != "-n" && string(out) != "preserved") {
			t.Fatalf("other shell/noninteractive source changed shell: %s %q: %v %s", tc.shell, tc.args, err, out)
		}
	}
}
