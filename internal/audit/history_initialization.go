package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const historyAuditScriptPath = "/etc/profile.d/history-audit.sh"

// A receipt is embedded in the encrypted command state before replacing the
// known faulty writer. It authorizes recovery of that generation only, and only
// while the repaired script and the retained log prefix still match.
type historyScriptRecovery struct {
	Version       int           `json:"version"`
	Source        string        `json:"source"`
	Generation    string        `json:"generation"`
	ScriptPath    string        `json:"script_path"`
	UpdatedSHA256 string        `json:"updated_sha256"`
	Log           authLogCursor `json:"log"`
	Anchor        string        `json:"anchor"`
}

func initializeHistoryScript(c Config, writer io.Writer) error {
	if runtime.GOOS != "linux" || c.History == nil || !c.History.Enabled || c.History.Path != "/var/log/history.log" {
		return nil
	}
	return initializeHistoryScriptAt(c, writer, historyAuditScriptPath)
}

func initializeHistoryScriptAt(c Config, writer io.Writer, scriptPath string) error {
	if c.History == nil || !c.History.Enabled {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
		return err
	}
	unlock, err := lockState(c.StateFile + ".commands.lock")
	if err != nil {
		return err
	}
	defer unlock()
	repair, err := repairHistoryScript(scriptPath, func(repair historyScriptRepair) error {
		// Deferring startup logging changes no source bytes. It must never
		// authorize replay/reset of an otherwise valid command cursor.
		if !repair.AppendRepaired {
			return migrateHistoryScriptRecoveryHash(c, scriptPath, repair)
		}
		return recordHistoryScriptRecovery(c, scriptPath, repair.UpdatedSHA256)
	})
	if err != nil {
		return fmt.Errorf("history script initialization failed: %w", err)
	}
	if repair.Repaired {
		return writeLog(c, writer, time.Now(), "history_script_repaired", map[string]any{
			"path": scriptPath, "backup": repair.BackupPath,
			"append_repaired": repair.AppendRepaired, "prompt_deferred": repair.PromptDeferred,
			"message": "updated the known history audit writer; existing interactive shells must reconnect to load the updated hook",
		})
	}
	return nil
}

// An older Agent may have repaired the writer but not yet consumed its
// recovery receipt. A prompt-only upgrade may update that existing receipt's
// script hash; it cannot create a receipt or alter its source/generation/log.
func migrateHistoryScriptRecoveryHash(c Config, scriptPath string, repair historyScriptRepair) error {
	var s historyState
	if err := readState(c.StateFile+".commands", "history", &s); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("preserve command state during prompt upgrade: %w", err)
	}
	r := s.ScriptRepair
	source := loginDigest(c.History.Path + "\x00" + c.History.Timezone)
	if r == nil || !validHistoryState(s, source) || r.Version != 1 || r.Source != s.Source ||
		r.Generation != s.Generation || r.ScriptPath != scriptPath || r.UpdatedSHA256 != repair.OriginalSHA256 {
		return nil
	}
	r.UpdatedSHA256 = repair.UpdatedSHA256
	return writeState(c.StateFile+".commands", "history", s)
}

func recordHistoryScriptRecovery(c Config, scriptPath, updatedSHA256 string) error {
	var s historyState
	if err := readState(c.StateFile+".commands", "history", &s); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("preserve existing command state before repairing its writer: %w", err)
	}
	source := loginDigest(c.History.Path + "\x00" + c.History.Timezone)
	if !validHistoryState(s, source) || s.Cursor.Offset == 0 {
		return nil
	}
	f, err := os.Open(c.History.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("history log must be a regular file")
	}
	log := authLogCursor{Identity: authIdentity(info), Offset: info.Size(), PrefixBytes: int(min(info.Size(), 256))}
	log.Prefix, err = authPrefix(f, log.PrefixBytes)
	if err != nil {
		return err
	}
	anchor, err := historyAnchor(f, log.Offset)
	if err != nil {
		return err
	}
	s.ScriptRepair = &historyScriptRecovery{1, source, s.Generation, scriptPath, updatedSHA256, log, anchor}
	return writeState(c.StateFile+".commands", "history", s)
}

func validHistoryState(s historyState, source string) bool {
	return s.Version == 1 && s.Source == source && len(s.Generation) == 32 && s.Cursor.Offset >= 0 && s.Cursor.PrefixBytes >= 0 && s.Cursor.PrefixBytes <= 256 && int64(s.Cursor.PrefixBytes) <= s.Cursor.Offset
}

// Called under the command-state lock, after all durable Pending records have
// been acknowledged. Other source changes retain the original refusal policy.
func recoverHistoryAfterScriptRepair(c Config, s *historyState, writer io.Writer) (bool, error) {
	r := s.ScriptRepair
	if r == nil || r.Version != 1 || r.Source != s.Source || r.Generation != s.Generation || len(s.Pending) != 0 {
		return false, nil
	}
	if r.Log.Offset < 0 || r.Log.PrefixBytes < 0 || r.Log.PrefixBytes > 256 || int64(r.Log.PrefixBytes) > r.Log.Offset {
		return false, fmt.Errorf("invalid history script repair receipt; preserve the encrypted command state")
	}
	// A receipt persisted before rename is not permission to reset if the
	// replacement failed, or if another tool subsequently changed the script.
	script, _, err := readHistoryScript(r.ScriptPath)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(script)
	if hex.EncodeToString(digest[:]) != r.UpdatedSHA256 {
		return false, nil
	}
	f, err := os.Open(c.History.Path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() < r.Log.Offset || (r.Log.Identity != "" && authIdentity(info) != r.Log.Identity) {
		return false, fmt.Errorf("history log changed again after script repair; existing shells may still use the old writer; preserve the log and command state")
	}
	prefix, prefixErr := authPrefix(f, r.Log.PrefixBytes)
	anchor, anchorErr := historyAnchor(f, r.Log.Offset)
	if prefixErr != nil || anchorErr != nil || prefix != r.Log.Prefix || anchor != r.Anchor {
		return false, fmt.Errorf("history log changed again after script repair; existing shells may still use the old writer; preserve the log and command state")
	}
	archive, err := archiveHistoryCommandState(c.StateFile + ".commands")
	if err != nil {
		return false, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, err
	}
	next := historyState{Version: 1, Source: s.Source, Generation: hex.EncodeToString(random[:])}
	// Consuming the receipt and selecting a new generation are one atomic
	// encrypted-state write. A restart cannot reuse the reset authorization.
	if err := writeState(c.StateFile+".commands", "history", next); err != nil {
		return false, err
	}
	*s = next
	if err := writeLog(c, writer, time.Now(), "history_cursor_recovered", map[string]string{
		"path": c.History.Path, "state_backup": archive,
		"message": "pending commands were acknowledged; restarted reading retained history after repairing the known truncating writer; overwritten commands cannot be recovered",
	}); err != nil {
		return true, err
	}
	return true, nil
}

func archiveHistoryCommandState(path string) (string, error) {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// A failed state replacement may be retried every second. Reuse an
	// identical content-addressed archive instead of growing backups per retry.
	digest := sha256.Sum256(ciphertext)
	name := path + ".before-script-repair-" + hex.EncodeToString(digest[:])
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		info, statErr := os.Lstat(name)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len(ciphertext)) {
			return "", fmt.Errorf("existing history recovery archive is not the expected regular file")
		}
		existing, openErr := os.Open(name)
		if openErr != nil {
			return "", openErr
		}
		defer existing.Close()
		opened, statErr := existing.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			return "", fmt.Errorf("history recovery archive changed while opening")
		}
		data, readErr := io.ReadAll(io.LimitReader(existing, int64(len(ciphertext))+1))
		if readErr != nil || !bytes.Equal(data, ciphertext) {
			return "", fmt.Errorf("existing history recovery archive does not match the encrypted command state")
		}
		return name, nil
	}
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(ciphertext); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}
