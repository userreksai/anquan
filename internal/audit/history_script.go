package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const maxHistoryScriptBytes = 1 << 20

// Only recognize the known audit helper and its locked append statement. Do not
// rewrite arbitrary shell redirects or replace an administrator's custom hook.
var (
	historyScriptFunction = regexp.MustCompile(`(?m)^[ \t]*_audit_log\(\)[ \t]*\{[ \t]*\r?$`)
	historyScriptTrap     = regexp.MustCompile(`(?m)^[ \t]*trap[ \t]+('_audit_log'|"_audit_log"|_audit_log)[ \t]+DEBUG[ \t]*\r?$`)
	historyScriptRedirect = regexp.MustCompile(`(?m)(^[ \t]*\{[ \t]*flock[ \t]+-x[ \t]+200;[^\r\n]*>>[ \t]+/var/log/history\.log[^\r\n]*;[ \t]*\}[ \t]+200)>(/var/log/history\.log[ \t]*\r?$)`)
)

func patchHistoryScript(original []byte) ([]byte, bool) {
	if len(original) > maxHistoryScriptBytes || bytes.IndexByte(original, 0) >= 0 || !historyScriptFunction.Match(original) || !historyScriptTrap.Match(original) {
		return original, false
	}
	if !historyScriptRedirect.Match(original) {
		return original, false
	}
	return historyScriptRedirect.ReplaceAll(original, []byte(`${1}>>${2}`)), true
}

type historyScriptRepair struct {
	Repaired       bool
	BackupPath     string
	OriginalSHA256 string
	UpdatedSHA256  string
}

// repairHistoryScript never creates a missing hook. Before replacing a known
// broken hook it saves a unique original and lets the caller durably prepare any
// recovery receipt. Repaired is true only after replacement; callers must also
// verify UpdatedSHA256 before trusting a receipt left by an interrupted attempt.
func repairHistoryScript(path string, beforeReplace func(historyScriptRepair) error) (historyScriptRepair, error) {
	var result historyScriptRepair
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return result, nil
	}
	if err := verifyHistoryScriptParents(path); err != nil {
		return result, err
	}
	original, info, err := readHistoryScript(path)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	updated, changed := patchHistoryScript(original)
	if !changed {
		return result, nil
	}
	originalHash, updatedHash := sha256.Sum256(original), sha256.Sum256(updated)
	result.OriginalSHA256 = hex.EncodeToString(originalHash[:])
	result.UpdatedSHA256 = hex.EncodeToString(updatedHash[:])
	backup, err := writeHistoryScriptTemp(path, "."+filepath.Base(path)+".anquan-before-append-*", original, info)
	if err != nil {
		return result, fmt.Errorf("backup history audit script: %w", err)
	}
	result.BackupPath = backup
	temporary, err := writeHistoryScriptTemp(path, ".anquan-history-script-*", updated, info)
	if err != nil {
		return result, fmt.Errorf("prepare history audit script: %w", err)
	}
	defer os.Remove(temporary)
	if err := verifyHistoryScriptUnchanged(path, original, info); err != nil {
		return result, err
	}
	if beforeReplace != nil {
		if err := beforeReplace(result); err != nil {
			return result, fmt.Errorf("prepare history script recovery: %w", err)
		}
	}
	if err := verifyHistoryScriptUnchanged(path, original, info); err != nil {
		return result, err
	}
	if err := os.Rename(temporary, path); err != nil {
		return result, fmt.Errorf("replace history audit script: %w", err)
	}
	result.Repaired = true
	return result, nil
}

func verifyHistoryScriptParents(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return fmt.Errorf("history audit script directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("history audit script directory must not be a symlink: %s", parent)
		}
		if next := filepath.Dir(parent); next == parent {
			return nil
		}
	}
}

func readHistoryScript(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("history audit script must be a regular file without symlinks: %s", path)
	}
	if info.Size() > maxHistoryScriptBytes {
		return nil, nil, fmt.Errorf("history audit script exceeds 1 MiB: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("history audit script changed before reading: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHistoryScriptBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxHistoryScriptBytes {
		return nil, nil, fmt.Errorf("history audit script exceeds 1 MiB: %s", path)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(info, after) || info.Size() != int64(len(data)) || !info.ModTime().Equal(after.ModTime()) || info.Mode() != after.Mode() || !sameHistoryScriptOwner(info, after) {
		return nil, nil, fmt.Errorf("history audit script changed during reading: %s", path)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, nil, fmt.Errorf("history audit script contains a NUL byte: %s", path)
	}
	return data, info, nil
}

func verifyHistoryScriptUnchanged(path string, original []byte, info os.FileInfo) error {
	if err := verifyHistoryScriptParents(path); err != nil {
		return err
	}
	data, current, err := readHistoryScript(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) || info.Mode() != current.Mode() || !info.ModTime().Equal(current.ModTime()) || !sameHistoryScriptOwner(info, current) || !bytes.Equal(data, original) {
		return fmt.Errorf("history audit script changed before replacement: %s", path)
	}
	return nil
}

func writeHistoryScriptTemp(path, pattern string, data []byte, source os.FileInfo) (name string, err error) {
	f, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return "", err
	}
	name = f.Name()
	createdName := name
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(createdName)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = preserveHistoryScriptOwner(f, source); err != nil {
		return "", err
	}
	if err = f.Chmod(source.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return name, nil
}
