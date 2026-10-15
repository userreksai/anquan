package audit

import (
	"path/filepath"
	"runtime"
	"strings"
)

const installedAgentDirectory = "/usr/local/anquan"
const systemAgentRuntimeDirectory = "/run/anquan"

// Only the fixed Linux installation uses the volatile system runtime directory.
// Custom deployments retain their local paths and need no access to /run.
func systemRuntimeResource(path string) (string, bool) {
	if runtime.GOOS != "linux" || !filepath.IsAbs(path) {
		return "", false
	}
	relative, err := filepath.Rel(installedAgentDirectory, filepath.Clean(path))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func usesSystemRuntimeDirectory(baseDir string) bool {
	relative, ok := systemRuntimeResource(baseDir)
	return ok && relative == "."
}
