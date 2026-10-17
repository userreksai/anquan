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
