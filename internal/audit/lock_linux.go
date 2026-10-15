//go:build linux

package audit

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

func lockState(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return lockLinuxFile(f, path)
}

// Lock a stable directory inode instead of creating a service lock file.
// Keep the directory after release: unlinking it could let another process
// lock a new inode while the original inode is still locked.
func lockService(path string) (func(), error) {
	dir := serviceLockDirectory(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	return lockLinuxFile(f, path)
}

func lockLinuxFile(f *os.File, path string) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another run holds %s: %w", path, errStateLockBusy)
		}
		return nil, fmt.Errorf("another run holds %s (or locking failed): %w", path, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() })
	}, nil
}
