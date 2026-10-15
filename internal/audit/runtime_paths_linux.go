//go:build linux

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Validate every component before creating the next one. MkdirAll could follow
// a pre-existing symlink, allowing a runtime socket or lock to escape /run.
func prepareSystemRuntimeDirectory(path string, mode os.FileMode) error {
	return walkSystemRuntimeDirectory(path, func(path string, root bool) error {
		if root {
			return verifySSHExecutionDirectory(path)
		}
		permission := mode
		if path == systemAgentRuntimeDirectory {
			// Ordinary SSH users must be able to traverse the socket's parent.
			permission = 0755
		}
		return ensureRootRuntimeDirectory(path, permission)
	})
}

func verifySystemRuntimeDirectory(path string) error {
	return walkSystemRuntimeDirectory(path, func(path string, _ bool) error {
		return verifySSHExecutionDirectory(path)
	})
}

func walkSystemRuntimeDirectory(path string, visit func(string, bool) error) error {
	path = filepath.Clean(path)
	relative, err := filepath.Rel(systemAgentRuntimeDirectory, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("runtime directory is outside %s", systemAgentRuntimeDirectory)
	}
	parent := filepath.Dir(systemAgentRuntimeDirectory)
	if err := visit(parent, true); err != nil {
		return err
	}
	if err := visit(systemAgentRuntimeDirectory, false); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	current := systemAgentRuntimeDirectory
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		if err := visit(current, false); err != nil {
			return err
		}
	}
	return nil
}

func ensureRootRuntimeDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return err
	}
	if err := verifySSHExecutionDirectory(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
