package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anqu/internal/sealed"
)

func readHistoryRecoveryState(t *testing.T, c Config) historyState {
	t.Helper()
	var s historyState
	if err := readState(c.StateFile+".commands", "history", &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func historyRecoveryArchives(t *testing.T, c Config) []string {
	t.Helper()
	paths, err := filepath.Glob(c.StateFile + ".commands.before-script-repair-*")
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func prepareHistoryRecoveryScript(t *testing.T, c Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history-audit.sh")
	put(t, path, brokenHistoryScript)
	if err := initializeHistoryScriptAt(c, nil, path); err != nil {
		t.Fatal(err)
	}
	if read(t, path) != fixedHistoryScript() {
		t.Fatal("initialization did not repair the known truncating writer")
	}
	return path
}

func assertHistoryRecoveryCommands(t *testing.T, events []historyEvent, want ...string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("events=%d commands=%d: %+v", len(events), len(want), events)
	}
	for i, command := range want {
		var record CommandRecord
		if events[i].Type != "command_history" || json.Unmarshal(events[i].Data, &record) != nil || record.Command != command {
			t.Fatalf("event %d did not retain command %q: %+v", i, command, events[i])
		}
	}
}

func TestHistoryScriptRecoveryArchivesEncryptedStateAndResetsOnce(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	var oldEvents []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		oldEvents = append(oldEvents, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old := readHistoryRecoveryState(t, c)
	put(t, c.History.Path, historyLine("new command")) // Same size: an old shell replaced consumed bytes.
	prepareHistoryRecoveryScript(t, c)
	prepared := readHistoryRecoveryState(t, c)
	if prepared.ScriptRepair == nil || prepared.Generation != old.Generation || prepared.ScriptRepair.Generation != old.Generation || prepared.ScriptRepair.Source != old.Source {
		t.Fatalf("repair did not bind the existing cursor generation: %+v", prepared)
	}
	preparedCiphertext := read(t, c.StateFile+".commands")
	// Normal appends after repair must remain collectible along with the retained
	// pre-repair line; the recovery receipt does not require an idle source.
	retained := historyLine("new command") + historyLine("after repair")
	put(t, c.History.Path, retained)
	var recovered []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		recovered = append(recovered, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertHistoryRecoveryCommands(t, recovered, "new command", "after repair")
	after := readHistoryRecoveryState(t, c)
	if after.Generation == old.Generation || after.ScriptRepair != nil || len(after.Pending) != 0 || after.Cursor.Offset != int64(len(retained)) {
		t.Fatalf("recovery was not consumed with the new generation: %+v", after)
	}
	if recovered[0].ID == oldEvents[0].ID || read(t, c.History.Path) != retained {
		t.Fatal("recovery reused old event identity or modified source log")
	}
	archives := historyRecoveryArchives(t, c)
	if len(archives) != 1 || read(t, archives[0]) != preparedCiphertext || !sealed.IsState([]byte(read(t, archives[0]))) {
		t.Fatalf("old encrypted cursor was not archived intact: %v", archives)
	}
	before := read(t, c.StateFile+".commands")
	put(t, c.History.Path, historyLine("bad command"))
	if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { t.Fatal("unrelated truncation was sent"); return nil }); err == nil || read(t, c.StateFile+".commands") != before {
		t.Fatal("one-use repair authorization was reused after a later truncation")
	}
	if len(historyRecoveryArchives(t, c)) != 1 {
		t.Fatal("unrelated truncation archived/reset the cursor")
	}
}

func TestHistoryScriptRecoveryRetriesPendingBeforeReset(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	failure := errors.New("master not reachable")
	var initial []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		initial = append(initial, events...)
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal("initial pending delivery did not fail as arranged")
	}
	old := readHistoryRecoveryState(t, c)
	put(t, c.History.Path, historyLine("new command"))
	prepareHistoryRecoveryScript(t, c)
	preparedCiphertext := read(t, c.StateFile+".commands")
	var retried []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		retried = append(retried, events...)
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal("pending failure was hidden by recovery")
	}
	if len(retried) != 1 || retried[0].ID != initial[0].ID || read(t, c.StateFile+".commands") != preparedCiphertext || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("failed pending retry changed identity or reset the cursor")
	}
	var acked []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		acked = append(acked, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	afterACK := readHistoryRecoveryState(t, c)
	if len(acked) != 1 || acked[0].ID != initial[0].ID || afterACK.Generation != old.Generation || len(afterACK.Pending) != 0 || afterACK.ScriptRepair == nil || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatalf("ACK did not drain old pending before a later reset: %+v", afterACK)
	}
	var newEvents []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		newEvents = append(newEvents, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertHistoryRecoveryCommands(t, newEvents, "new command")
	if final := readHistoryRecoveryState(t, c); final.Generation == old.Generation || final.ScriptRepair != nil {
		t.Fatalf("drained generation was not recovered on the next poll: %+v", final)
	}
}

func TestHistoryScriptRecoveryConsumesUnneededReceiptOnIdleRead(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	send := func(Config, []historyEvent) error { return nil }
	if _, err := pollHistory(c, nil, send); err != nil {
		t.Fatal(err)
	}
	old := readHistoryRecoveryState(t, c)
	prepareHistoryRecoveryScript(t, c)
	if readHistoryRecoveryState(t, c).ScriptRepair == nil {
		t.Fatal("fixture did not write a receipt")
	}
	if more, err := pollHistory(c, nil, func(Config, []historyEvent) error { t.Fatal("idle poll replayed commands"); return nil }); err != nil || more {
		t.Fatalf("idle poll failed: more=%v err=%v", more, err)
	}
	after := readHistoryRecoveryState(t, c)
	if after.Generation != old.Generation || after.ScriptRepair != nil || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("valid idle source reset unnecessarily or retained future reset permission")
	}
	before := read(t, c.StateFile+".commands")
	if _, err := pollHistory(c, nil, send); err != nil || read(t, c.StateFile+".commands") != before {
		t.Fatal("subsequent idle poll rewrote the consumed receipt")
	}
	put(t, c.History.Path, historyLine("new command"))
	if _, err := pollHistory(c, nil, send); err == nil || read(t, c.StateFile+".commands") != before {
		t.Fatal("unrelated source change reused an idle repair receipt")
	}
}

func TestHistoryScriptRecoveryRequiresCompletedScriptReplacement(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	send := func(Config, []historyEvent) error { return nil }
	if _, err := pollHistory(c, nil, send); err != nil {
		t.Fatal(err)
	}
	put(t, c.History.Path, historyLine("new command"))
	script := filepath.Join(t.TempDir(), "history-audit.sh")
	put(t, script, brokenHistoryScript)
	fixedHash := sha256.Sum256([]byte(fixedHistoryScript()))
	// Simulate a crash/failure after durable preparation but before rename.
	if err := recordHistoryScriptRecovery(c, script, hex.EncodeToString(fixedHash[:])); err != nil {
		t.Fatal(err)
	}
	before := read(t, c.StateFile+".commands")
	if _, err := pollHistory(c, nil, send); err == nil || read(t, c.StateFile+".commands") != before || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("a receipt without the fixed writer authorized reset")
	}
}

func TestHistoryScriptRecoveryRejectsAnotherRewriteAfterRepair(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("old command"))
	send := func(Config, []historyEvent) error { return nil }
	if _, err := pollHistory(c, nil, send); err != nil {
		t.Fatal(err)
	}
	put(t, c.History.Path, historyLine("new command"))
	prepareHistoryRecoveryScript(t, c)
	before := read(t, c.StateFile+".commands")
	put(t, c.History.Path, historyLine("bad command"))
	if _, err := pollHistory(c, nil, send); err == nil || !strings.Contains(err.Error(), "changed again") || read(t, c.StateFile+".commands") != before || len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("an old terminal's later rewrite was silently accepted")
	}
}

func TestHistoryScriptRecoveryKeepsChangedSourceAndCorruptState(t *testing.T) {
	for _, changeSource := range []bool{false, true} {
		t.Run(map[bool]string{false: "timezone", true: "path"}[changeSource], func(t *testing.T) {
			c := historyTestConfig(t)
			put(t, c.History.Path, historyLine("old command"))
			send := func(Config, []historyEvent) error { return nil }
			if _, err := pollHistory(c, nil, send); err != nil {
				t.Fatal(err)
			}
			put(t, c.History.Path, historyLine("new command"))
			prepareHistoryRecoveryScript(t, c)
			before := read(t, c.StateFile+".commands")
			if changeSource {
				c.History.Path += ".other"
				put(t, c.History.Path, historyLine("new command"))
			} else {
				c.History.Timezone = "Asia/Shanghai"
			}
			if _, err := pollHistory(c, nil, send); err == nil || !strings.Contains(err.Error(), "source/timezone changed") || read(t, c.StateFile+".commands") != before || len(historyRecoveryArchives(t, c)) != 0 {
				t.Fatal("repair receipt allowed an unrelated configuration change")
			}
		})
	}

	t.Run("corrupt", func(t *testing.T) {
		c := historyTestConfig(t)
		put(t, c.History.Path, historyLine("new command"))
		put(t, c.StateFile+".commands", "damaged encrypted state")
		script := filepath.Join(t.TempDir(), "history-audit.sh")
		put(t, script, brokenHistoryScript)
		if err := initializeHistoryScriptAt(c, nil, script); err == nil {
			t.Fatal("corrupt state was ignored during repair preparation")
		}
		if read(t, c.StateFile+".commands") != "damaged encrypted state" || read(t, script) != brokenHistoryScript {
			t.Fatal("corrupt cursor or unprepared writer was overwritten")
		}
		if _, err := os.Stat(c.StateFile + ".commands"); err != nil {
			t.Fatal("corrupt command state was removed")
		}
	})
}
