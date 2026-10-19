package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const brokenHistoryScript = `# 命令审计配置 - 所有终端命令集中记录
export HISTSIZE=0
export HISTFILESIZE=0
unset HISTFILE
export PROMPT_COMMAND=''

_audit_log() {
    [ -z "$BASH_COMMAND" ] && return
    case "$BASH_COMMAND" in
        _audit_log*|*"_audit_log"*) return ;;
        *"history"*|*"tty"*|*"whoami"*) return ;;
    esac
    local user tty_name ts
    user=$(whoami 2>/dev/null || echo "unknown")
    tty_name=$(tty 2>/dev/null || echo "-")
    ts=$(date +"%F %T")
    { flock -x 200; echo "[$ts] [$user] [$tty_name] [$BASH_COMMAND]" >> /var/log/history.log 2>/dev/null; } 200>/var/log/history.log
}

trap '_audit_log' DEBUG
`

func fixedHistoryScript() string {
	return strings.ReplaceAll(brokenHistoryScript, "} 200>/var/log/history.log", "} 200>>/var/log/history.log")
}

func initializedHistoryScript() string {
	updated, _ := patchHistoryPromptScript([]byte(fixedHistoryScript()))
	return string(updated)
}

func TestPatchHistoryScriptOnlyKnownTruncation(t *testing.T) {
	for _, tc := range []struct {
		name, original, want string
		changed              bool
	}{
		{"known", brokenHistoryScript, fixedHistoryScript(), true},
		{"crlf", strings.ReplaceAll(brokenHistoryScript, "\n", "\r\n"), strings.ReplaceAll(fixedHistoryScript(), "\n", "\r\n"), true},
		{"fixed", fixedHistoryScript(), fixedHistoryScript(), false},
		{"unknown", "echo custom > /var/log/history.log\n", "echo custom > /var/log/history.log\n", false},
		{"different_function", strings.ReplaceAll(brokenHistoryScript, "_audit_log", "custom_logger"), strings.ReplaceAll(brokenHistoryScript, "_audit_log", "custom_logger"), false},
		{"different_target", strings.ReplaceAll(brokenHistoryScript, "/var/log/history.log", "/tmp/custom.log"), strings.ReplaceAll(brokenHistoryScript, "/var/log/history.log", "/tmp/custom.log"), false},
		{"no_lock", strings.ReplaceAll(brokenHistoryScript, "flock -x 200;", "true;"), strings.ReplaceAll(brokenHistoryScript, "flock -x 200;", "true;"), false},
		{"no_trap", strings.ReplaceAll(brokenHistoryScript, "trap '_audit_log' DEBUG", "# hook disabled"), strings.ReplaceAll(brokenHistoryScript, "trap '_audit_log' DEBUG", "# hook disabled"), false},
		{"no_append_writer", strings.ReplaceAll(brokenHistoryScript, "]\" >> /var/log/history.log", "]\" > /var/log/history.log"), strings.ReplaceAll(brokenHistoryScript, "]\" >> /var/log/history.log", "]\" > /var/log/history.log"), false},
		{"nul", brokenHistoryScript + "\x00", brokenHistoryScript + "\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := patchHistoryScript([]byte(tc.original))
			if string(got) != tc.want || changed != tc.changed {
				t.Fatalf("changed=%v want=%v script=%q", changed, tc.changed, got)
			}
		})
	}
}

func TestRepairHistoryScriptBackupAndIdempotence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history-audit.sh")
	if err := os.WriteFile(path, []byte(brokenHistoryScript), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	result, err := repairHistoryScript(path, func(planned historyScriptRepair) error {
		called++
		if planned.Repaired || planned.BackupPath == "" || planned.OriginalSHA256 == "" || planned.UpdatedSHA256 == "" {
			t.Fatalf("unexpected plan: %+v", planned)
		}
		if got := read(t, path); got != brokenHistoryScript {
			t.Fatal("script changed before durable preparation")
		}
		if got := read(t, planned.BackupPath); got != brokenHistoryScript {
			t.Fatal("preparation did not receive a complete backup")
		}
		return nil
	})
	if err != nil || !result.Repaired || called != 1 {
		t.Fatalf("result=%+v callback=%d err=%v", result, called, err)
	}
	if got := read(t, path); got != initializedHistoryScript() || !result.AppendRepaired || !result.PromptDeferred {
		t.Fatal("known writer was not repaired and deferred until the first prompt")
	}
	if got := read(t, result.BackupPath); got != brokenHistoryScript {
		t.Fatal("original backup changed")
	}
	updatedHash := sha256.Sum256([]byte(initializedHistoryScript()))
	if result.UpdatedSHA256 != hex.EncodeToString(updatedHash[:]) {
		t.Fatal("replacement digest does not identify installed bytes")
	}
	for _, name := range []string{path, result.BackupPath} {
		after, err := os.Stat(name)
		if err != nil || !sameHistoryScriptOwner(before, after) || before.Mode().Perm() != after.Mode().Perm() {
			t.Fatalf("metadata changed: %s %v", name, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || strings.HasSuffix(result.BackupPath, ".sh") {
		t.Fatal("temporary file leaked or backup could be sourced as another profile script")
	}
	again, err := repairHistoryScript(path, func(historyScriptRepair) error {
		t.Fatal("idempotent repair called preparation")
		return nil
	})
	if err != nil || again.Repaired || again.BackupPath != "" {
		t.Fatalf("repeat result=%+v err=%v", again, err)
	}
	entries, _ = os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatal("idempotent repair created another backup")
	}
	// A later administrator reintroduction gets its own backup, never overwriting
	// the original or a pre-existing conventional .bak file.
	put(t, path, brokenHistoryScript)
	put(t, path+".bak", "administrator backup")
	second, err := repairHistoryScript(path, nil)
	if err != nil || !second.Repaired || second.BackupPath == result.BackupPath {
		t.Fatalf("second repair=%+v err=%v", second, err)
	}
	if read(t, path+".bak") != "administrator backup" || read(t, result.BackupPath) != brokenHistoryScript {
		t.Fatal("existing backup overwritten")
	}
}

func TestRepairHistoryScriptLeavesMissingAndCustomScripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-parent", "history-audit.sh")
	result, err := repairHistoryScript(path, nil)
	if err != nil || result.Repaired {
		t.Fatalf("missing hook: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("missing hook created directories")
	}
	path = filepath.Join(t.TempDir(), "custom.sh")
	put(t, path, "# custom audit script\necho custom\n")
	result, err = repairHistoryScript(path, nil)
	if err != nil || result.Repaired || result.BackupPath != "" || read(t, path) != "# custom audit script\necho custom\n" {
		t.Fatalf("custom hook altered: %+v %v", result, err)
	}
}

func TestRepairHistoryScriptPreparationFailureKeepsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history-audit.sh")
	put(t, path, brokenHistoryScript)
	failure := errors.New("cannot persist recovery authorization")
	result, err := repairHistoryScript(path, func(historyScriptRepair) error { return failure })
	if !errors.Is(err, failure) || result.Repaired || result.BackupPath == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if read(t, path) != brokenHistoryScript || read(t, result.BackupPath) != brokenHistoryScript {
		t.Fatal("failed preparation changed the script or backup")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatal("temporary replacement leaked after preparation failure")
	}
}

func TestRepairHistoryScriptRefusesChangedSource(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "edited", true: "replaced"}[replace], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "history-audit.sh")
			put(t, path, brokenHistoryScript)
			result, err := repairHistoryScript(path, func(historyScriptRepair) error {
				if replace {
					if err := os.Remove(path); err != nil {
						return err
					}
				}
				return os.WriteFile(path, []byte("# administrator edit\n"), 0600)
			})
			if err == nil || result.Repaired || read(t, path) != "# administrator edit\n" {
				t.Fatalf("concurrent edit overwritten: %+v %v", result, err)
			}
		})
	}
}

func TestRepairHistoryScriptRejectsUnsafeInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"oversized", bytes.Repeat([]byte("x"), maxHistoryScriptBytes+1)},
		{"nul", append([]byte(brokenHistoryScript), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "history-audit.sh")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := repairHistoryScript(path, nil)
			if err == nil || result.Repaired || result.BackupPath != "" {
				t.Fatalf("unsafe input accepted: %+v %v", result, err)
			}
		})
	}

	t.Run("directory", func(t *testing.T) {
		result, err := repairHistoryScript(t.TempDir(), nil)
		if err == nil || result.Repaired {
			t.Fatalf("directory accepted: %+v %v", result, err)
		}
	})

	for _, parentLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "symlink_file", true: "symlink_parent"}[parentLink], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "original.sh")
			put(t, target, brokenHistoryScript)
			path := filepath.Join(dir, "history-audit.sh")
			linkTarget := target
			if parentLink {
				linkTarget = dir
			}
			if err := os.Symlink(linkTarget, path); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symlink privilege unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if parentLink {
				path = filepath.Join(path, "original.sh")
			}
			result, err := repairHistoryScript(path, nil)
			if err == nil || result.Repaired || read(t, target) != brokenHistoryScript {
				t.Fatalf("symlink followed: %+v %v", result, err)
			}
		})
	}
}
