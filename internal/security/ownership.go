package security

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
)

func managedModeMatches(actual, want os.FileMode) bool {
	// Windows managers only run against test roots and cannot represent Unix
	// permissions. Linux production requires the complete expected mode.
	return runtime.GOOS == "windows" || actual == want
}

// referenceExistingFile checks whether an unowned file can be used as-is.
// An exact match never grants permission to change its contents or permissions,
// or to remove it when the component is disabled.
func (m *Manager) referenceExistingFile(path string, want managedFile) (bool, error) {
	full := m.path(path)
	if err := noSymlink(full); err != nil {
		return false, err
	}
	info, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	conflict := func() (bool, error) {
		return false, fmt.Errorf("managed path %s already exists without agent ownership and does not match the requested configuration; restore the original security-managed.state or back up and relocate the conflicting file before retrying", path)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(want.Data)) ||
		!managedModeMatches(info.Mode(), want.Mode) {
		return conflict()
	}
	f, err := os.Open(full)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !os.SameFile(info, opened) {
		return conflict()
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(len(want.Data))+1))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, want.Data) {
		return conflict()
	}
	return true, nil
}
