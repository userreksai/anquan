//go:build !linux

package audit

import (
	"context"
	"fmt"
	"io"
	"os"
)

func RequestHistoryCommand(context.Context, string, string) error {
	return fmt.Errorf("command recording IPC is supported only on Linux")
}

func serveHistoryCommands(context.Context, Config, io.Writer) error { return nil }
func preflightHistoryCommands(Config) error                         { return nil }

func verifyHistoryManagedParents(path string) error { return verifyHistoryScriptParents(path) }
func verifyHistoryManagedOwner(os.FileInfo) bool    { return true }

// The portable implementation supports hermetic initialization tests. Linux
// additionally verifies kernel ownership and opens with O_NOFOLLOW.
func ensureHistoryCommandLog(path string) (bool, error) {
	if err := verifyHistoryScriptParents(path); err != nil {
		return false, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("command log must be a regular file without symlinks")
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
		if err != nil {
			return false, err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return false, fmt.Errorf("command log changed before normalization")
		}
		if err := f.Chmod(0644); err != nil {
			return false, err
		}
		return false, f.Sync()
	} else if !os.IsNotExist(err) {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		return ensureHistoryCommandLog(path)
	}
	if err != nil {
		return false, err
	}
	return true, f.Close()
}
