package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"
)

type Config struct {
	OutputDir string          `json:"output_dir"`
	StateFile string          `json:"state_file"`
	Timezone  string          `json:"timezone"`
	MD5       MD5Config       `json:"md5"`
	Login     LoginConfig     `json:"login"`
	Existence ExistenceConfig `json:"existence"`
	location  *time.Location
}

type MD5Config struct {
	Enabled      bool     `json:"enabled"`
	Paths        []string `json:"paths"`
	Recursive    bool     `json:"recursive"`
	ExcludePaths []string `json:"exclude_paths"`
}

type LoginConfig struct {
	Enabled        bool   `json:"enabled"`
	Source         string `json:"source"`
	Path           string `json:"path"`
	LastCommand    string `json:"last_command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxRecords     int    `json:"max_records"`
}

type ExistenceConfig struct {
	Enabled  bool   `json:"enabled"`
	ListFile string `json:"list_file"`
	BaseDir  string `json:"base_dir"`
}

type CheckEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func readJSON(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Accept UTF-8 BOM written by some Windows editors.
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s: expected exactly one JSON value", path)
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	c := Config{
		OutputDir: "/usr/local/anqu", StateFile: "state/md5.json", Timezone: "Asia/Shanghai",
		MD5:       MD5Config{Enabled: true, Recursive: true},
		Login:     LoginConfig{Enabled: true, Source: "wtmp", Path: "/var/log/wtmp", LastCommand: "last", TimeoutSeconds: 10, MaxRecords: 1000},
		Existence: ExistenceConfig{Enabled: true},
	}
	if err := readJSON(path, &c); err != nil {
		return c, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return c, err
	}
	base := filepath.Dir(absolute)
	if strings.TrimSpace(c.OutputDir) == "" || strings.TrimSpace(c.StateFile) == "" {
		return c, fmt.Errorf("output_dir and state_file cannot be empty")
	}
	c.OutputDir = resolve(base, c.OutputDir)
	c.StateFile = resolve(c.OutputDir, c.StateFile)
	c.location, err = time.LoadLocation(c.Timezone)
	if err != nil {
		return c, fmt.Errorf("timezone: %w", err)
	}
	if c.MD5.Enabled {
		if len(c.MD5.Paths) == 0 {
			return c, fmt.Errorf("md5.paths cannot be empty when enabled")
		}
		for i, p := range c.MD5.Paths {
			if strings.TrimSpace(p) == "" {
				return c, fmt.Errorf("empty md5.paths entry")
			}
			c.MD5.Paths[i] = resolve(base, p)
		}
		for i, p := range c.MD5.ExcludePaths {
			if strings.TrimSpace(p) == "" {
				return c, fmt.Errorf("empty md5.exclude_paths entry")
			}
			c.MD5.ExcludePaths[i] = resolve(base, p)
		}
		c.MD5.Paths = uniqueSorted(c.MD5.Paths)
		c.MD5.ExcludePaths = uniqueSorted(c.MD5.ExcludePaths)
		for _, p := range c.MD5.Paths {
			if excluded(c, p) {
				return c, fmt.Errorf("MD5 root %s is excluded (including output/state paths)", p)
			}
		}
	}
	if c.Login.Enabled {
		if c.Login.Source != "wtmp" && c.Login.Source != "jsonl" {
			return c, fmt.Errorf("login.source must be wtmp or jsonl")
		}
		if strings.TrimSpace(c.Login.Path) == "" {
			return c, fmt.Errorf("login.path cannot be empty")
		}
		c.Login.Path = resolve(base, c.Login.Path)
		if c.Login.LastCommand == "" || c.Login.TimeoutSeconds < 1 || c.Login.TimeoutSeconds > 3600 || c.Login.MaxRecords < 1 || c.Login.MaxRecords > 100000 {
			return c, fmt.Errorf("invalid login command, timeout_seconds (1..3600) or max_records (1..100000)")
		}
	}
	if c.Existence.Enabled {
		if strings.TrimSpace(c.Existence.ListFile) == "" || strings.TrimSpace(c.Existence.BaseDir) == "" {
			return c, fmt.Errorf("existence.list_file and base_dir are required")
		}
		c.Existence.ListFile = resolve(base, c.Existence.ListFile)
		c.Existence.BaseDir = resolve(base, c.Existence.BaseDir)
		if _, err := loadChecks(c.Existence); err != nil {
			return c, err
		}
	}
	return c, nil
}

func loadChecks(c ExistenceConfig) ([]CheckEntry, error) {
	var entries []CheckEntry
	if err := readJSON(c.ListFile, &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("existence list cannot be empty")
	}
	seen := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if strings.TrimSpace(e.Path) == "" {
			return nil, fmt.Errorf("empty path in existence list")
		}
		if e.Type == "" {
			e.Type = "file"
		}
		if e.Type != "file" && e.Type != "directory" && e.Type != "any" {
			return nil, fmt.Errorf("invalid existence type %q", e.Type)
		}
		if !filepath.IsAbs(e.Path) {
			p := resolve(c.BaseDir, e.Path)
			if !inside(c.BaseDir, p) {
				return nil, fmt.Errorf("relative check path %q escapes base_dir; use an explicit absolute path", e.Path)
			}
			e.Path = p
		} else {
			e.Path = filepath.Clean(e.Path)
		}
		if seen[e.Path] {
			return nil, fmt.Errorf("duplicate existence path %s", e.Path)
		}
		seen[e.Path] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func resolve(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(base, path)
}

func inside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func uniqueSorted(paths []string) []string {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
