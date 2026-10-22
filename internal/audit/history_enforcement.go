package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type historyScriptSync struct {
	Changed    bool
	Replaced   bool
	BackupPath string
}

// Compare the complete script, not just a version marker: administrators and
// previous releases may have left a different writer behind the same marker.
func syncHistoryScriptAt(scriptPath, logPath, binaryPath string, beforeReplace func(historyScriptRepair) error) (historyScriptSync, error) {
	var result historyScriptSync
	if err := verifyHistoryManagedParents(scriptPath); err != nil {
		return result, err
	}
	original, info, err := readHistoryScript(scriptPath)
	if err != nil && !os.IsNotExist(err) {
		return result, err
	}
	exists := err == nil
	if _, err := ensureHistoryCommandLog(logPath); err != nil {
		return result, err
	}
	wanted := managedHistoryScript(binaryPath)
	if exists && bytes.Equal(original, wanted) && hasManagedHistoryScriptPermissions(info) {
		return result, nil
	}
	if exists {
		result.BackupPath, err = writeHistoryScriptTemp(scriptPath, "."+filepath.Base(scriptPath)+".anquan-before-managed-*", original, info)
		if err != nil {
			return result, fmt.Errorf("backup existing history script: %w", err)
		}
	}
	f, err := os.CreateTemp(filepath.Dir(scriptPath), ".anquan-history-install-*")
	if err != nil {
		return result, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := setManagedHistoryScriptPermissions(f); err != nil {
		return result, err
	}
	if _, err := f.Write(wanted); err != nil {
		return result, err
	}
	if err := f.Sync(); err != nil {
		return result, err
	}
	if err := f.Close(); err != nil {
		return result, err
	}
	if err := verifyHistoryManagedParents(scriptPath); err != nil {
		return result, err
	}
	if exists {
		if err := verifyHistoryScriptUnchanged(scriptPath, original, info); err != nil {
			return result, err
		}
		if beforeReplace != nil {
			oldHash, newHash := sha256.Sum256(original), sha256.Sum256(wanted)
			if err := beforeReplace(historyScriptRepair{
				OriginalSHA256: hex.EncodeToString(oldHash[:]), UpdatedSHA256: hex.EncodeToString(newHash[:]),
			}); err != nil {
				return result, fmt.Errorf("preserve command state before history replacement: %w", err)
			}
		}
		if err := verifyHistoryScriptUnchanged(scriptPath, original, info); err != nil {
			return result, err
		}
		if err := os.Rename(f.Name(), scriptPath); err != nil {
			return result, fmt.Errorf("replace history script: %w", err)
		}
		result.Replaced = true
	} else if err := os.Link(f.Name(), scriptPath); err != nil {
		// A competing creator must be checked on the next initialization; it
		// must never make an incompatible writer count as successful setup.
		return result, fmt.Errorf("install history script without replacing a concurrent creator: %w", err)
	}
	result.Changed = true
	if runtime.GOOS == "linux" {
		dir, err := os.Open(filepath.Dir(scriptPath))
		if err != nil {
			return result, err
		}
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return result, err
		}
	}
	return result, nil
}

func enforceHistoryManagedAt(c Config, writer io.Writer, scriptPath, logPath, binaryPath string) error {
	allowAppendRecovery := c.History != nil && c.History.Path == "/var/log/history.log"
	return enforceHistoryManagedWithRecoveryPolicy(c, writer, scriptPath, logPath, binaryPath, allowAppendRecovery)
}

func enforceHistoryManagedWithRecoveryPolicy(c Config, writer io.Writer, scriptPath, logPath, binaryPath string, allowAppendRecovery bool) error {
	if c.History == nil || !c.History.Enabled {
		return nil
	}
	if err := validateHistoryManagedLogPath(c, scriptPath, logPath, binaryPath); err != nil {
		return err
	}
	// Keep the old truncation recovery path before switching writers. The
	// subsequent replacement only migrates an already valid receipt's hash.
	// The recognized legacy writer targets /var/log/history.log; repairing it
	// must never authorize resetting an unrelated custom source's cursor.
	if err := initializeHistoryScriptAtWithRecoveryPolicy(c, writer, scriptPath, allowAppendRecovery); err != nil {
		return err
	}
	unlock, err := lockState(c.StateFile + ".commands.lock")
	if err != nil {
		return err
	}
	defer unlock()
	result, err := syncHistoryScriptAt(scriptPath, logPath, binaryPath, func(repair historyScriptRepair) error {
		return migrateHistoryScriptRecoveryHash(c, scriptPath, repair)
	})
	if err != nil {
		return fmt.Errorf("history script installation failed: %w", err)
	}
	if result.Changed {
		event := "history_script_installed"
		if result.Replaced {
			event = "history_script_replaced"
		}
		return writeLog(c, writer, time.Now(), event, map[string]string{
			"path": scriptPath, "backup": result.BackupPath,
			"message": "enforced the Agent command format and managed hook; existing interactive shells must reconnect to load it",
		})
	}
	return nil
}

// A source that used to be read-only must not become a writable command log
// when it aliases the Agent's own executable, hook, configuration or state.
func validateHistoryManagedLogPath(c Config, scriptPath, logPath, binaryPath string) error {
	rules := nativePathRules()
	logKey := rules.key(logPath)
	protected := []string{scriptPath, binaryPath}
	if c.StateFile != "" {
		stateKey := rules.key(c.StateFile)
		if logKey == stateKey || strings.HasPrefix(logKey, stateKey+".") {
			return fmt.Errorf("history.path must not overlap Agent state files")
		}
	}
	if c.runtimeDir != "" {
		for _, name := range []string{"config.age", "config.master.age", "agent.connection.age", "agent.connection.json"} {
			protected = append(protected, filepath.Join(c.runtimeDir, name))
		}
	}
	if c.Login.Path != "" {
		protected = append(protected, c.Login.Path)
	}
	for _, path := range protected {
		if logKey == rules.key(path) {
			return fmt.Errorf("history.path must not overlap the Agent hook, executable, configuration or login source")
		}
	}
	return nil
}
