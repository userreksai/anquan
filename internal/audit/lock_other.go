//go:build !linux && !windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Portable fallback for local development. Linux and Windows use OS file locks.
func lockState(path string) (func(), error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("cannot lock %s: %w", path, err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

func lockService(path string) (func(), error) {
	dir := serviceLockDirectory(path)
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	return lockState(dir)
}
