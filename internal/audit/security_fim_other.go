//go:build !linux

package audit

import (
	"context"
	"os"
)

func nativeOwnership(os.FileInfo) (uint32, uint32, string) { return 0, 0, "" }

// Non-Linux development runs retain periodic snapshot detection.
func watchNativePaths(context.Context, []string, func(string) bool, ...func(string, uint32) *nativeFile) (<-chan nativeWatchEvent, func()) {
	ch := make(chan nativeWatchEvent)
	close(ch)
	return ch, func() {}
}
