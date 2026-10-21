//go:build linux

package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func nativeOwnership(info os.FileInfo) (uint32, uint32, string) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, stat.Gid, fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return 0, 0, ""
}

func watchNativePaths(parent context.Context, roots []string, excluded func(string) bool, captures ...func(string, uint32) *nativeFile) (<-chan nativeWatchEvent, func()) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan nativeWatchEvent, 1024)
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		ch <- nativeWatchEvent{Err: err}
		close(ch)
		return ch, cancel
	}
	done := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(done)
		defer close(ch)
		defer syscall.Close(fd)
		watches := map[int]string{}
		watched := map[string]bool{}
		initializing := true
		push := func(event nativeWatchEvent) bool {
			// Setup may encounter many unwatchable roots before the consumer
			// receives readiness. Never deadlock startup on diagnostic overflow.
			if initializing && event.Err != nil {
				select {
				case ch <- event:
				default:
				}
				return ctx.Err() == nil
			}
			select {
			case ch <- event:
				return true
			case <-ctx.Done():
				return false
			}
		}
		add := func(path string) error {
			if excluded(path) {
				return nil
			}
			if watched[path] {
				return nil
			}
			if len(watches) >= 10000 {
				return fmt.Errorf("native FIM exceeds 10000 directory watches")
			}
			wd, err := syscall.InotifyAddWatch(fd, path, syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_MODIFY|syscall.IN_ATTRIB|syscall.IN_MOVED_FROM|syscall.IN_MOVED_TO|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF|syscall.IN_CLOSE_WRITE)
			if err != nil {
				return err
			}
			if previous, exists := watches[wd]; exists && previous != path {
				delete(watched, previous)
			}
			watches[wd] = path
			watched[path] = true
			return nil
		}
		refresh := func() {
			for _, root := range roots {
				ancestor := filepath.Dir(root)
				for {
					if info, err := os.Stat(ancestor); err == nil && info.IsDir() {
						if err := add(ancestor); err != nil {
							push(nativeWatchEvent{Path: ancestor, Err: err})
						}
						break
					}
					next := filepath.Dir(ancestor)
					if next == ancestor {
						break
					}
					ancestor = next
				}
				_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if walkErr != nil {
						return nil
					}
					if excluded(path) {
						if entry.IsDir() {
							return filepath.SkipDir
						}
						return nil
					}
					if entry.IsDir() {
						if err := add(path); err != nil {
							push(nativeWatchEvent{Path: path, Err: err})
							return filepath.SkipDir
						}
					}
					return nil
				})
			}
		}
		refresh()
		initializing = false
		close(ready)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		buffer := make([]byte, 64<<10)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			refreshNeeded := false
			for {
				n, err := syscall.Read(fd, buffer)
				if errors.Is(err, syscall.EAGAIN) {
					break
				}
				if err != nil {
					if !push(nativeWatchEvent{Err: err}) {
						return
					}
					break
				}
				if n == 0 {
					break
				}
				for offset := 0; offset+16 <= n; {
					wd := int(int32(binary.NativeEndian.Uint32(buffer[offset:])))
					mask := binary.NativeEndian.Uint32(buffer[offset+4:])
					nameLen := int(binary.NativeEndian.Uint32(buffer[offset+12:]))
					if offset+16+nameLen > n {
						break
					}
					name := strings.TrimRight(string(buffer[offset+16:offset+16+nameLen]), "\x00")
					offset += 16 + nameLen
					if mask&syscall.IN_Q_OVERFLOW != 0 {
						if !push(nativeWatchEvent{Err: fmt.Errorf("inotify queue overflow; periodic reconciliation required")}) {
							return
						}
						refreshNeeded = true
						continue
					}
					parentPath, exists := watches[wd]
					if !exists {
						continue
					}
					path := parentPath
					if name != "" {
						path = filepath.Join(parentPath, name)
					}
					if mask&syscall.IN_IGNORED != 0 {
						delete(watches, wd)
						delete(watched, parentPath)
						refreshNeeded = true
						continue
					}
					relevant := nativeInScope(path, roots)
					for _, root := range roots {
						relevant = relevant || inside(path, root)
					}
					if relevant && !excluded(path) {
						activity := nativeWatchEvent{Path: path, Mask: mask, At: time.Now().UTC()}
						if len(captures) > 0 {
							activity.Snapshot = captures[0](path, mask)
						}
						if !push(activity) {
							return
						}
					}
					if mask&(syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF) != 0 {
						delete(watches, wd)
						delete(watched, parentPath)
						_, _ = syscall.InotifyRmWatch(fd, uint32(wd))
					}
					if mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0 {
						refreshNeeded = true
					}
				}
			}
			if refreshNeeded {
				refresh()
			}
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
	}
	return ch, func() { cancel(); <-done }
}
