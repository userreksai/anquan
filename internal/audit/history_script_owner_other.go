//go:build !linux

package audit

import "os"

func preserveHistoryScriptOwner(_ *os.File, _ os.FileInfo) error { return nil }

func sameHistoryScriptOwner(_, _ os.FileInfo) bool { return true }
