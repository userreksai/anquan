package audit

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anqu/internal/security"
)

type nativeFile struct {
	Type           string `json:"type"`
	SHA256         string `json:"sha256,omitempty"`
	Mode           uint32 `json:"mode"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	Size           int64  `json:"size"`
	Modified       int64  `json:"modified_ns"`
	Inode          string `json:"inode,omitempty"`
	Link           string `json:"link,omitempty"`
	Text           string `json:"text,omitempty"`
	ContentTracked bool   `json:"content_tracked,omitempty"`
	ContentStatus  string `json:"content_status,omitempty"`
	TextTruncated  bool   `json:"text_truncated,omitempty"`
}

type nativeFIMState struct {
	Version    int                   `json:"version"`
	Generation string                `json:"generation"`
	Sequence   uint64                `json:"sequence"`
	Roots      []string              `json:"roots"`
	Files      map[string]nativeFile `json:"files"`
	Pending    *nativeFIMChange      `json:"pending,omitempty"`
	Backlog    []nativeFIMChange     `json:"backlog,omitempty"`
}

type nativeFIMChange struct {
	Event security.Event `json:"event"`
	Path  string         `json:"path"`
	After *nativeFile    `json:"after,omitempty"`
}

func commitNativeFIMChange(path string, state *nativeFIMState, emit func(security.Event) error) error {
	for state.Pending != nil || len(state.Backlog) > 0 {
		if state.Pending == nil {
			state.Pending = &state.Backlog[0]
			state.Backlog = state.Backlog[1:]
		}
		if err := emit(state.Pending.Event); err != nil {
			return err
		}
		if state.Pending.After == nil {
			delete(state.Files, state.Pending.Path)
		} else {
			state.Files[state.Pending.Path] = *state.Pending.After
		}
		state.Pending = nil
		if err := writeState(path, "security-fim", state); err != nil {
			return err
		}
	}
	return nil
}

type nativeWatchEvent struct {
	Path     string
	Mask     uint32
	Err      error
	Snapshot *nativeFile
	At       time.Time
}

func nativeSensitivePath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	name := filepath.Base(p)
	for _, part := range []string{"/.ssh/", "/ssl/private/", "shadow", "secret", "credential", "password"} {
		if strings.Contains(p, part) {
			return true
		}
	}
	return strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".pem") || strings.HasPrefix(name, "id_")
}

func nativeInScope(path string, roots []string) bool {
	for _, root := range roots {
		if inside(root, path) {
			return true
		}
	}
	return false
}

func nativeExcluded(c Config, path string) bool {
	if nativeEditorTemporary(path) {
		explicit := false
		if c.Security != nil && c.Security.NativeFIM != nil {
			for _, root := range c.Security.NativeFIM.Paths {
				if filepath.Clean(root) == filepath.Clean(path) {
					explicit = true
					break
				}
			}
		}
		if !explicit {
			return true
		}
	}
	if inside(c.OutputDir, path) || inside(securityDataDir(c), path) || path == c.StateFile || strings.HasPrefix(path, c.StateFile+".") {
		return true
	}
	if c.Setup != nil && (path == c.Setup.Prom || path == logPath(c, time.Now())) {
		return true
	}
	if c.Setup != nil {
		if filepath.Dir(path) == filepath.Dir(c.Setup.Prom) && strings.HasPrefix(filepath.Base(path), ".anqu-") && strings.HasSuffix(path, ".tmp") {
			return true
		}
		now := time.Now()
		current := logPath(c, now)
		if filepath.Dir(path) == filepath.Dir(current) {
			name, want := filepath.Base(path), filepath.Base(current)
			date := now.In(beijing).Format("20060102")
			pos := strings.Index(want, date)
			if pos >= 0 && len(name) == len(want) && name[:pos] == want[:pos] && name[pos+8:] == want[pos+8:] {
				digits := true
				for _, ch := range name[pos : pos+8] {
					if ch < '0' || ch > '9' {
						digits = false
					}
				}
				if digits {
					return true
				}
			}
		}
	}
	return false
}

func nativeFileInfo(ctx context.Context, path string, cfg *NativeFIMConfig) (nativeFile, error) {
	return nativeReadFile(ctx, path, cfg, cfg.ReportChanges, false)
}
func nativeSnapshot(ctx context.Context, c Config, prior ...*nativeFIMState) (map[string]nativeFile, error) {
	result := map[string]nativeFile{}
	cfg := c.Security.NativeFIM
	var state *nativeFIMState
	if len(prior) > 0 {
		state = prior[0]
	}
	for _, root := range cfg.Paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if nativeExcluded(c, root) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				if path == root && os.IsNotExist(walkErr) {
					result[root] = nativeFile{Type: "missing"}
					return nil
				}
				if os.IsNotExist(walkErr) {
					return nil
				}
				return walkErr
			}
			if nativeExcluded(c, path) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if len(result) >= 50000 {
				return fmt.Errorf("native FIM exceeds 50000 entries")
			}
			tracked := false
			if state != nil {
				before, had := nativeEffectiveFile(state, path)
				tracked = before.ContentTracked
				if nativeCaptureCreated(cfg) && (!had || before.Type == "missing" || before.Type != "file") && nativeInScope(path, state.Roots) {
					tracked = true
				}
			}
			item, err := nativeReadFile(ctx, path, cfg, cfg.ReportChanges || (tracked && nativeCaptureCreated(cfg)), tracked)
			if err != nil {
				return err
			}
			result[path] = item
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
