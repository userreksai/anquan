//go:build !linux

package audit

import (
	"fmt"
	"os"
)

// Portable fallback for local development. Linux uses automatically released flock.
func lockState(path string) (func(), error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("cannot lock %s: %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
}
