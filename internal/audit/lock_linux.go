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
	_, system := systemRuntimeResource(path)
	if system {
		if err := prepareSystemRuntimeDirectory(dir, 0700); err != nil {
			return nil, err
		}
	} else {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	legacy := ""
	if system {
		legacy = legacyServiceLockDirectory(path)
	}
	return lockServiceDirectories(path, dir, legacy)
}

// During an upgrade, an old process may still hold the installation-tree lock.
// Keep that existing inode locked too, without recreating obsolete directories.
func lockServiceDirectories(path, dir, legacy string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	unlock, err := lockLinuxFile(f, path)
	if err != nil || legacy == "" {
		return unlock, err
	}
	legacyInfo, err := os.Lstat(legacy)
	if os.IsNotExist(err) {
		return unlock, nil
	}
	if err != nil {
		unlock()
		return nil, err
	}
	if !legacyInfo.IsDir() || !sshExecutionRootOwned(legacyInfo) || legacyInfo.Mode().Perm()&0022 != 0 {
		unlock()
		return nil, fmt.Errorf("legacy service lock must be a root-owned directory not writable by other users: %s", legacy)
	}
	legacyFile, err := os.Open(legacy)
	if err != nil {
		unlock()
		return nil, err
	}
	openedInfo, err := legacyFile.Stat()
	if err != nil || !os.SameFile(legacyInfo, openedInfo) {
		_ = legacyFile.Close()
		unlock()
		return nil, fmt.Errorf("legacy service lock changed before locking: %s", legacy)
	}
	legacyUnlock, err := lockLinuxFile(legacyFile, path)
	if err != nil {
		unlock()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { legacyUnlock(); unlock() }) }, nil
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
