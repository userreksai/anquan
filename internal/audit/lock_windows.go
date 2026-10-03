//go:build windows

package audit

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	lockKernel32     = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc   = lockKernel32.NewProc("LockFileEx")
	unlockFileExProc = lockKernel32.NewProc("UnlockFileEx")
)

func lockState(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	const lockFileFailImmediately = 0x1
	const lockFileExclusiveLock = 0x2
	var overlapped syscall.Overlapped
	ok, _, callErr := lockFileExProc.Call(
		f.Fd(), lockFileFailImmediately|lockFileExclusiveLock, 0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	runtime.KeepAlive(f)
	if ok == 0 {
		_ = f.Close()
		return nil, fmt.Errorf("another run holds %s (or locking failed): %w", path, callErr)
	}
	// Windows releases this lock if the process exits, including forced termination.
	// Keep the file in place so every run locks the same file.
	var once sync.Once
	return func() {
		once.Do(func() {
			_, _, _ = unlockFileExProc.Call(
				f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)),
			)
			_ = f.Close()
		})
	}, nil
}
