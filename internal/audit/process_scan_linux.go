//go:build linux

package audit

import "os"

func scanSystemProcesses() (map[string]int, error) {
	return scanProcProcesses("/proc", os.Getpid())
}
