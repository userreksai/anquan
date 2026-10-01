//go:build linux

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func lockState(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another run holds %s (or locking failed): %w", path, err)
	}
	// Leave the inode in place; unlinking it would permit two independent locks.
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
