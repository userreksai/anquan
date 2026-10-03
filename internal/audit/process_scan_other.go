//go:build !linux

package audit

import (
	"fmt"
	"runtime"
)

func scanSystemProcesses() (map[string]int, error) {
	return nil, fmt.Errorf("ProcessMonitoring requires Linux /proc; current OS is %s", runtime.GOOS)
}
