package audit

import (
	"errors"
	"path/filepath"
)

var errStateLockBusy = errors.New("state resource is locked by another check")

// Each resource gets its own stable directory so a service's configuration
// cache and scan state can be protected independently, even in one directory.
func serviceLockDirectory(path string) string {
	return filepath.Join(filepath.Dir(path), ".anqu-service-locks", filepath.Base(path))
}
