package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHistoryPromptPatchPreservesCustomHooksAndIsIdempotent(t *testing.T) {
	for _, prompt := range []string{"export PROMPT_COMMAND=''", "PROMPT_COMMAND='custom_prompt # keep this comment'", "PROMPT_COMMAND=(first_prompt second_prompt)"} {
		original := strings.Replace(fixedHistoryScript(), "export PROMPT_COMMAND=''", prompt, 1)
		patched, changed := patchHistoryPromptScript([]byte(original))
		if !changed || !bytes.Contains(patched, []byte("# anquan-history-prompt-gate-v1")) {
			t.Fatal("known append writer was not upgraded")
		}
		if prompt != "export PROMPT_COMMAND=''" && !bytes.Contains(patched, []byte(prompt)) {
			t.Fatalf("custom prompt hook was removed: %s", prompt)
		}
		if bytes.Contains(patched, []byte("export PROMPT_COMMAND=''")) || !bytes.Contains(patched, []byte("200>>/var/log/history.log")) {
			t.Fatal("prompt clearing or truncating redirect remains")
		}
		again, changed := patchHistoryPromptScript(patched)
		if changed || !bytes.Equal(patched, again) {
			t.Fatal("prompt patch was not idempotent")
		}
	}
	crlf, changed := patchHistoryPromptScript([]byte(strings.ReplaceAll(fixedHistoryScript(), "\n", "\r\n")))
	if !changed || strings.Contains(strings.ReplaceAll(string(crlf), "\r\n", ""), "\n") {
		t.Fatal("CRLF writer was not preserved")
	}
}

func TestHistoryPromptPatchLeavesUnknownWriters(t *testing.T) {
	for _, original := range []string{
		brokenHistoryScript,
		strings.ReplaceAll(fixedHistoryScript(), "_audit_log", "custom_log"),
		strings.ReplaceAll(fixedHistoryScript(), "/var/log/history.log", "/tmp/custom.log"),
		fixedHistoryScript() + "\ntrap '_audit_log' DEBUG\n",
	} {
		patched, changed := patchHistoryPromptScript([]byte(original))
		if changed || string(patched) != original {
			t.Fatal("unrecognized or ambiguous hook was changed")
		}
	}
}

func TestHistoryPromptUpgradeNeverAuthorizesCursorRecovery(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "pending"}[pending], func(t *testing.T) {
			c := historyTestConfig(t)
			put(t, c.History.Path, historyLine("already collected"))
			if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if pending {
				s := readHistoryRecoveryState(t, c)
				s.Pending = []historyEvent{{ID: "pending-before-upgrade", Type: "command_history"}}
				if err := writeState(c.StateFile+".commands", "history", s); err != nil {
					t.Fatal(err)
				}
			}
			before := read(t, c.StateFile+".commands")
			path := filepath.Join(t.TempDir(), "history-audit.sh")
			put(t, path, fixedHistoryScript())
			if err := initializeHistoryScriptAt(c, nil, path); err != nil {
				t.Fatal(err)
			}
			if read(t, path) != initializedHistoryScript() || read(t, c.StateFile+".commands") != before {
				t.Fatal("prompt-only upgrade changed the encrypted cursor or pending batch")
			}
			if readHistoryRecoveryState(t, c).ScriptRepair != nil || len(historyRecoveryArchives(t, c)) != 0 {
				t.Fatal("prompt-only upgrade authorized replay of historical commands")
			}
		})
	}
}

func TestHistoryPromptUpgradePreservesExistingAppendRecovery(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	failure := errors.New("pending ACK")
	var initial []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		initial = append(initial, events...)
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	// Simulate an older Agent which already fixed the append writer and
	// authorized recovery, but still has a batch awaiting acknowledgement.
	put(t, c.History.Path, historyLine("new command"))
	path := filepath.Join(t.TempDir(), "history-audit.sh")
	put(t, path, fixedHistoryScript())
	oldHash := sha256.Sum256([]byte(fixedHistoryScript()))
	if err := recordHistoryScriptRecovery(c, path, hex.EncodeToString(oldHash[:])); err != nil {
		t.Fatal(err)
	}
	before := readHistoryRecoveryState(t, c)
	if err := initializeHistoryScriptAt(c, nil, path); err != nil {
		t.Fatal(err)
	}
	after := readHistoryRecoveryState(t, c)
	newHash := sha256.Sum256([]byte(initializedHistoryScript()))
	before.ScriptRepair.UpdatedSHA256 = hex.EncodeToString(newHash[:])
	if !reflect.DeepEqual(before, after) || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("prompt upgrade changed the existing receipt, cursor or pending records beyond the script hash")
	}
	var acked []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		acked = append(acked, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(acked) != 1 || acked[0].ID != initial[0].ID {
		t.Fatal("prompt upgrade changed the pending retry identity")
	}
	var recovered []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		recovered = append(recovered, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertHistoryRecoveryCommands(t, recovered, "new command")
	if readHistoryRecoveryState(t, c).ScriptRepair != nil || len(historyRecoveryArchives(t, c)) != 1 {
		t.Fatal("existing append recovery was not consumed exactly once")
	}
}
