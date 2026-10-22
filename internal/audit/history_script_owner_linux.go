//go:build linux

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func preserveHistoryScriptOwner(file *os.File, original os.FileInfo) error {
	owner, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("history audit script owner is unavailable")
	}
	return file.Chown(int(owner.Uid), int(owner.Gid))
}

func sameHistoryScriptOwner(before, after os.FileInfo) bool {
	a, first := before.Sys().(*syscall.Stat_t)
	b, second := after.Sys().(*syscall.Stat_t)
	return first && second && a.Uid == b.Uid && a.Gid == b.Gid
}

func setManagedHistoryScriptPermissions(file *os.File) error {
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	return file.Chmod(0644)
}

func hasManagedHistoryScriptPermissions(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == 0 && owner.Gid == 0 && info.Mode().Perm() == 0644 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}
