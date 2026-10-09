package audit

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type baseline struct {
	Version    int               `json:"version"`
	Scope      string            `json:"scope"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Files      map[string]string `json:"files"`
	Cumulative map[string]uint64 `json:"changes_total"`
	LastChange *time.Time        `json:"last_change_at,omitempty"`
}

func excluded(c Config, path string) bool {
	if inside(c.OutputDir, path) || path == c.StateFile || inside(c.StateFile+".lock", path) {
		return true
	}
	for _, p := range c.MD5.ExcludePaths {
		if inside(p, path) {
			return true
		}
	}
	return false
}

func scopeID(c Config) string {
	b, _ := json.Marshal(struct {
		MD5           MD5Config
		Output, State string
	}{c.MD5, c.OutputDir, c.StateFile})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func collectMD5(c Config, now time.Time) (MD5Result, *baseline, []Issue) {
	r := MD5Result{Enabled: c.MD5.Enabled, Success: true, Changes: []Change{}, MissingRoots: []string{}, Cumulative: map[string]uint64{"added": 0, "modified": 0, "deleted": 0}}
	if !r.Enabled {
		return r, nil, nil
	}
	var old baseline
	err := readBaseline(c, c.StateFile, "md5", &old)
	first := os.IsNotExist(err)
	if err != nil && !first {
		r.Success = false
		return r, nil, []Issue{{"md5", "read baseline: " + err.Error()}}
	}
	if !first {
		if old.Version != 1 || old.Files == nil || old.Cumulative == nil || old.Scope != scopeID(c) {
			r.Success = false
			return r, nil, []Issue{{"md5", "baseline is invalid or monitored paths/options changed; move the old state file aside to explicitly create a new baseline"}}
		}
		for p, hash := range old.Files {
			b, e := hex.DecodeString(hash)
			if !filepath.IsAbs(p) || e != nil || len(b) != md5.Size {
				r.Success = false
				return r, nil, []Issue{{"md5", "invalid baseline file/hash: " + p}}
			}
		}
		for kind := range r.Cumulative {
			r.Cumulative[kind] = old.Cumulative[kind]
		}
		r.LastChange = old.LastChange
	}
	files := map[string]string{}
	seen := map[string]bool{}
	var issues []Issue
	addError := func(p string, e error) { issues = append(issues, Issue{"md5", p + ": " + e.Error()}) }
	for _, root := range c.MD5.Paths {
		_, statErr := os.Lstat(root)
		if os.IsNotExist(statErr) && !first {
			r.MissingRoots = append(r.MissingRoots, root)
			continue
		}
		if statErr != nil {
			addError(root, statErr)
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if excluded(c, path) {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if walkErr != nil {
				addError(path, walkErr)
				return nil
			}
			if d.IsDir() {
				if path != root && !c.MD5.Recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true
			if !d.Type().IsRegular() {
				r.Skipped++
				return nil
			}
			hash, err := hashFile(path)
			if err != nil {
				addError(path, err)
				return nil
			}
			files[path] = hash
			return nil
		})
		if err != nil {
			addError(root, err)
		}
	}
	r.Scanned = len(files)
	if len(issues) > 0 {
		// Never convert an unreadable subtree into false deletions or move the baseline forward.
		r.Success = false
		return r, nil, issues
	}
	if !first {
		for path, hash := range files {
			before, exists := old.Files[path]
			if !exists {
				r.Changes = append(r.Changes, Change{Path: path, Kind: "added", After: hash})
			} else if before != hash {
				r.Changes = append(r.Changes, Change{Path: path, Kind: "modified", Before: before, After: hash})
			}
		}
		for path, before := range old.Files {
			if _, exists := files[path]; !exists {
				r.Changes = append(r.Changes, Change{Path: path, Kind: "deleted", Before: before})
			}
		}
	}
	sort.Slice(r.Changes, func(i, j int) bool { return r.Changes[i].Path < r.Changes[j].Path })
	for _, change := range r.Changes {
		r.Cumulative[change.Kind]++
	}
	if len(r.Changes) > 0 {
		r.LastChange = &now
	}
	r.BaselineCreated = first
	next := &baseline{Version: 1, Scope: scopeID(c), UpdatedAt: now, Files: files, Cumulative: r.Cumulative, LastChange: r.LastChange}
	return r, next, nil
}

func hashFile(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, opened) {
		return "", fmt.Errorf("file replaced while opening")
	}
	h := md5.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || n != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("file changed while hashing; retry on next run")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
