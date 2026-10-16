package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"anqu/internal/security"
)

type nativeFile struct {
	Type     string `json:"type"`
	SHA256   string `json:"sha256,omitempty"`
	Mode     uint32 `json:"mode"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified_ns"`
	Inode    string `json:"inode,omitempty"`
	Link     string `json:"link,omitempty"`
	Text     string `json:"text,omitempty"`
}

type nativeFIMState struct {
	Version    int                   `json:"version"`
	Generation string                `json:"generation"`
	Sequence   uint64                `json:"sequence"`
	Roots      []string              `json:"roots"`
	Files      map[string]nativeFile `json:"files"`
	Pending    *nativeFIMChange      `json:"pending,omitempty"`
}

type nativeFIMChange struct {
	Event security.Event `json:"event"`
	Path  string         `json:"path"`
	After *nativeFile    `json:"after,omitempty"`
}

func commitNativeFIMChange(path string, state *nativeFIMState, emit func(security.Event) error) error {
	if state.Pending == nil {
		return nil
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
	return writeState(path, "security-fim", state)
}

type nativeWatchEvent struct {
	Path string
	Mask uint32
	Err  error
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
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nativeFile{Type: "missing"}, nil
	}
	if err != nil {
		return nativeFile{}, err
	}
	uid, gid, inode := nativeOwnership(info)
	n := nativeFile{Type: "special", Mode: uint32(info.Mode()), UID: uid, GID: gid, Inode: inode, Size: info.Size(), Modified: info.ModTime().UnixNano()}
	if info.Mode()&os.ModeSymlink != 0 {
		n.Type = "symlink"
		n.Link, err = os.Readlink(path)
		return n, err
	}
	if info.IsDir() {
		n.Type = "directory"
		// Membership is checked independently; temporary child files should
		// not turn directory size/mtime into a self-generated content alert.
		n.Modified, n.Size = 0, 0
		return n, nil
	}
	if !info.Mode().IsRegular() {
		return n, nil
	}
	n.Type = "file"
	if info.Size() > 64<<20 {
		return n, fmt.Errorf("native FIM file exceeds 64 MiB limit: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return n, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return n, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return n, fmt.Errorf("file changed before hash: %s", path)
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var text []byte
	keepText := cfg.ReportChanges && !nativeSensitivePath(path) && info.Size() <= int64(cfg.MaxDiffBytes)
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		count, readErr := f.Read(buffer)
		if count > 0 {
			_, _ = h.Write(buffer[:count])
			if keepText {
				text = append(text, buffer[:count]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return n, readErr
		}
	}
	after, err := os.Lstat(path)
	if err != nil {
		return n, err
	}
	if !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || info.Mode() != after.Mode() {
		return n, fmt.Errorf("file changed during hash: %s", path)
	}
	n.SHA256 = hex.EncodeToString(h.Sum(nil))
	if keepText && utf8.Valid(text) && !strings.ContainsRune(string(text), 0) {
		n.Text = string(text)
	}
	return n, nil
}

func nativeSnapshot(ctx context.Context, c Config) (map[string]nativeFile, error) {
	result := map[string]nativeFile{}
	cfg := c.Security.NativeFIM
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
			item, err := nativeFileInfo(ctx, path, cfg)
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

// Unlike the legacy MD5 module this baseline is deliberately retained across
// restarts and configuration updates. New roots initialize independently.
func pollNativeFIM(ctx context.Context, c Config, emit func(security.Event) error) error {
	path := filepath.Join(securityDataDir(c), "native-fim.state")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	unlock, err := lockState(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	state := nativeFIMState{}
	if err := readState(path, "security-fim", &state); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		var generation [16]byte
		if _, err := rand.Read(generation[:]); err != nil {
			return err
		}
		state = nativeFIMState{Version: 1, Generation: hex.EncodeToString(generation[:]), Files: map[string]nativeFile{}}
	}
	if state.Version != 1 || state.Generation == "" || state.Files == nil {
		return fmt.Errorf("invalid persistent native FIM baseline")
	}
	if err := commitNativeFIMChange(path, &state, emit); err != nil {
		return err
	}
	next, err := nativeSnapshot(ctx, c)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(next)+len(state.Files))
	seen := map[string]bool{}
	for p := range next {
		paths = append(paths, p)
		seen[p] = true
	}
	for p := range state.Files {
		if !seen[p] && nativeInScope(p, c.Security.NativeFIM.Paths) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		before, had := state.Files[p]
		after, has := next[p]
		// Existing files in a newly assigned root form its initial baseline.
		if !nativeInScope(p, state.Roots) && has && after.Type != "missing" {
			continue
		}
		if had && has && before == after {
			continue
		}
		change := "modified"
		if !had {
			change = "added"
		}
		if !has {
			change = "deleted"
		}
		if has && after.Type == "missing" {
			change = "missing"
		}
		if had && before.Type == "missing" && has && after.Type != "missing" {
			change = "added"
		}
		if !had && has && after.Type == "directory" {
			continue
		}
		state.Sequence++
		id := fmt.Sprintf("native-fim:%s:%d", state.Generation, state.Sequence)
		beforeMeta, afterMeta := before, after
		beforeMeta.Text = ""
		afterMeta.Text = ""
		details := map[string]any{"change": change, "before": beforeMeta, "after": afterMeta, "baseline_persistent": true}
		if c.Security.NativeFIM.ReportChanges && !nativeSensitivePath(p) && (before.Text != "" || after.Text != "") {
			details["previous_text"] = before.Text
			details["current_text"] = after.Text
		}
		event := security.Event{ID: id, Type: "security_event", Time: time.Now().UTC(), Component: "native_fim", Message: "monitored file changed", Data: map[string]any{"source": "native_fim", "kind": "file_change", "severity": "warning", "path": p, "message": "monitored file " + change, "details": details}}
		if encoded,_:=json.Marshal(event.Data);len(encoded)>48000{delete(details,"previous_text");delete(details,"current_text");details["text_omitted_transport_limit"]=true}
		state.Pending = &nativeFIMChange{Event: event, Path: p}
		if has {
			copy := after
			state.Pending.After = &copy
		}
		// Reserve the identity and exact transition before any asynchronous
		// publisher can ACK it. Retries cannot assign it to another path.
		if err := writeState(path, "security-fim", state); err != nil {
			return err
		}
		if err := commitNativeFIMChange(path, &state, emit); err != nil {
			return err
		}
	}
	state.Roots = append([]string(nil), c.Security.NativeFIM.Paths...)
	state.Files = next
	return writeState(path, "security-fim", state)
}

func nativeFIMLoop(ctx context.Context, c Config, emit func(security.Event) error, health func(error)) {
	watch, closeWatch := watchNativePaths(ctx, c.Security.NativeFIM.Paths, func(path string) bool { return nativeExcluded(c, path) })
	defer closeWatch()
	health(pollNativeFIM(ctx, c, emit))
	ticker := time.NewTicker(time.Duration(c.Security.NativeFIM.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()
	var rescan <-chan time.Time
	var debounce *time.Timer
	defer func() {
		if debounce != nil {
			debounce.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case activity, ok := <-watch:
			if !ok {
				watch = nil
				continue
			}
			if activity.Path != "" && nativeExcluded(c, activity.Path) {
				continue
			}
			data := map[string]any{"source": "native_fim", "kind": "file_activity", "severity": "info", "path": activity.Path, "message": "kernel file notification", "details": map[string]any{"mask": activity.Mask}}
			if activity.Err != nil {
				data["kind"] = "watch_error"
				data["severity"] = "warning"
				data["message"] = activity.Err.Error()
				health(activity.Err)
			}
			if err := emit(security.Event{Type: "security_event", Time: time.Now().UTC(), Component: "native_fim", Data: data}); err != nil {
				health(err)
			}
			if rescan == nil {
				debounce = time.NewTimer(100 * time.Millisecond)
				rescan = debounce.C
			}
		case <-rescan:
			rescan = nil
			health(pollNativeFIM(ctx, c, emit))
		case <-ticker.C:
			health(pollNativeFIM(ctx, c, emit))
		}
	}
}
