package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryEnforcementPreparationFailureKeepsOriginal(t *testing.T) {
	dir := historyManagedInstallDir(t)
	script, log := filepath.Join(dir, "history-audit.sh"), filepath.Join(dir, "history.log")
	const original = "# external command writer\necho original\n"
	put(t, script, original)
	denied := errors.New("encrypted cursor cannot be preserved")
	result, err := syncHistoryScriptAt(script, log, historyCommandBinaryPath, func(historyScriptRepair) error { return denied })
	if !errors.Is(err, denied) || result.Changed || read(t, script) != original || read(t, result.BackupPath) != original {
		t.Fatalf("failed preparation replaced the old writer: %+v %v", result, err)
	}
}

func TestHistoryEnforcementRefusesConcurrentScriptChange(t *testing.T) {
	dir := historyManagedInstallDir(t)
	script, log := filepath.Join(dir, "history-audit.sh"), filepath.Join(dir, "history.log")
	put(t, script, "# external writer\n")
	result, err := syncHistoryScriptAt(script, log, historyCommandBinaryPath, func(historyScriptRepair) error {
		put(t, script, "# administrator changed it during setup\n")
		return nil
	})
	if err == nil || result.Changed || read(t, script) != "# administrator changed it during setup\n" {
		t.Fatalf("concurrent writer change was overwritten: %+v %v", result, err)
	}
}

func TestHistoryEnforcementKeepsPendingRetryAndAppendRecovery(t *testing.T) {
	dir := historyManagedInstallDir(t)
	c := historyTestConfig(t)
	c.History.Path = filepath.Join(dir, "history.log")
	put(t, c.History.Path, historyLine("old command"))
	var initial []historyEvent
	awaitingACK := errors.New("awaiting master ACK")
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		initial = append(initial, events...)
		return awaitingACK
	}); !errors.Is(err, awaitingACK) {
		t.Fatal(err)
	}
	put(t, c.History.Path, historyLine("new command"))
	script := filepath.Join(dir, "history-audit.sh")
	put(t, script, brokenHistoryScript)
	var output bytes.Buffer
	// The temporary source represents the legacy default log without touching
	// the host's /var/log. Production only enables this receipt for that source.
	if err := enforceHistoryManagedWithRecoveryPolicy(c, &output, script, c.History.Path, historyCommandBinaryPath, true); err != nil {
		t.Fatal(err)
	}
	if read(t, script) != string(managedHistoryScript(historyCommandBinaryPath)) || !strings.Contains(output.String(), "history_script_replaced") {
		t.Fatalf("old writer was not converted to the managed hook: %s", output.String())
	}
	s := readHistoryRecoveryState(t, c)
	digest := sha256.Sum256(managedHistoryScript(historyCommandBinaryPath))
	if s.ScriptRepair == nil || s.ScriptRepair.UpdatedSHA256 != hex.EncodeToString(digest[:]) || len(s.Pending) != 1 || s.Pending[0].ID != initial[0].ID {
		t.Fatal("conversion lost the pending retry or invalidated the existing recovery receipt")
	}
	var acked []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		acked = append(acked, events...)
		return nil
	}); err != nil || len(acked) != 1 || acked[0].ID != initial[0].ID {
		t.Fatalf("pending batch identity changed: %v %+v", err, acked)
	}
	var recovered []historyEvent
	if _, err := pollHistory(c, nil, func(_ Config, events []historyEvent) error {
		recovered = append(recovered, events...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertHistoryRecoveryCommands(t, recovered, "new command")
	if len(historyRecoveryArchives(t, c)) != 1 {
		t.Fatal("recovery did not retain the original encrypted state")
	}
}

func TestHistoryEnforcementDoesNotAuthorizeRecoveryForUnrelatedCustomSource(t *testing.T) {
	dir := historyManagedInstallDir(t)
	c := historyTestConfig(t)
	c.History.Path = filepath.Join(dir, "custom-history.log")
	put(t, c.History.Path, historyLine("old custom command"))
	if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := read(t, c.StateFile+".commands")
	put(t, c.History.Path, historyLine("new custom command"))
	script := filepath.Join(dir, "history-audit.sh")
	put(t, script, brokenHistoryScript)
	if err := initializeHistoryManagedAt(c, nil, script, c.History.Path, historyCommandBinaryPath); err != nil {
		t.Fatal(err)
	}
	if read(t, c.StateFile+".commands") != before || readHistoryRecoveryState(t, c).ScriptRepair != nil {
		t.Fatal("repairing a writer for another log authorized custom-source recovery")
	}
	sent := false
	if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { sent = true; return nil }); err == nil || sent {
		t.Fatalf("unknown custom-source rewrite was silently replayed: sent=%v err=%v", sent, err)
	}
	if len(historyRecoveryArchives(t, c)) != 0 {
		t.Fatal("unrelated custom command state was archived/reset")
	}
}

func TestHistoryEnforcementRejectsLogPathOverlappingAgentFiles(t *testing.T) {
	dir := historyManagedInstallDir(t)
	script, binary := filepath.Join(dir, "history-audit.sh"), filepath.Join(dir, "anquan")
	c := historyTestConfig(t)
	c.runtimeDir = dir
	c.Login.Path = filepath.Join(dir, "wtmp")
	for _, target := range []string{script, binary, c.StateFile, c.StateFile + ".commands", filepath.Join(dir, "config.master.age"), c.Login.Path} {
		if target == "" {
			continue
		}
		t.Run(filepath.Base(target), func(t *testing.T) {
			put(t, target, "retained Agent file\n")
			c.History.Path = target
			if err := initializeHistoryManagedAt(c, nil, script, target, binary); err == nil {
				t.Fatal("Agent file accepted as a managed writable history source")
			}
			if read(t, target) != "retained Agent file\n" {
				t.Fatal("invalid history configuration changed an Agent file")
			}
		})
	}
}
