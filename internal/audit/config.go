package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"

	"go.yaml.in/yaml/v3"
)

// JSON tags preserve internal MD5 scope fingerprints; user configuration is YAML.
type Config struct {
	OutputDir string          `json:"output_dir" yaml:"output_dir"`
	StateFile string          `json:"state_file" yaml:"state_file"`
	Timezone  string          `json:"timezone" yaml:"timezone"`
	MD5       MD5Config       `json:"md5" yaml:"md5"`
	Login     LoginConfig     `json:"login" yaml:"login"`
	Existence ExistenceConfig `json:"existence" yaml:"existence"`
	location  *time.Location
}

type MD5Config struct {
	Enabled      bool     `json:"enabled" yaml:"enabled"`
	Paths        []string `json:"paths" yaml:"paths"`
	Recursive    bool     `json:"recursive" yaml:"recursive"`
	ExcludePaths []string `json:"exclude_paths" yaml:"exclude_paths"`
}

type LoginConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Source         string `json:"source" yaml:"source"`
	Path           string `json:"path" yaml:"path"`
	LastCommand    string `json:"last_command" yaml:"last_command"`
	TimeoutSeconds int    `json:"timeout_seconds" yaml:"timeout_seconds"`
	MaxRecords     int    `json:"max_records" yaml:"max_records"`
}

type ExistenceConfig struct {
	Enabled bool         `json:"enabled" yaml:"enabled"`
	BaseDir string       `json:"base_dir" yaml:"base_dir"`
	Files   []CheckEntry `json:"files,omitempty" yaml:"files,omitempty"`
}

type CheckEntry struct {
	Path string `json:"path" yaml:"path"`
	Type string `json:"type" yaml:"type"`
}

func decodeYAML(data []byte) (Config, error) {
	c := Config{
		OutputDir: "/usr/local/anqu", StateFile: "state/md5.json", Timezone: "Asia/Shanghai",
		MD5:       MD5Config{Enabled: true, Recursive: true},
		Login:     LoginConfig{Enabled: true, Source: "wtmp", Path: "/var/log/wtmp", LastCommand: "last", TimeoutSeconds: 10, MaxRecords: 1000},
		Existence: ExistenceConfig{Enabled: true},
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if json.Valid(data) {
		return c, fmt.Errorf("JSON configuration is not supported; use YAML mapping syntax")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("YAML configuration: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("expected exactly one YAML document")
	}
	return c, nil
}

// LoadConfig is a build-time/development helper. Deployed agents use ParseConfig.
func LoadConfig(configPath string) (Config, error) {
	ext := strings.ToLower(filepath.Ext(configPath))
	if ext != ".yaml" && ext != ".yml" {
		return Config{}, fmt.Errorf("configuration must use .yaml or .yml: %s", configPath)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, err
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return Config{}, err
	}
	c, err := ParseConfig(data, filepath.Dir(absolute))
	if err != nil {
		return c, fmt.Errorf("%s: %w", configPath, err)
	}
	return c, nil
}

// ParseConfig validates without reading monitored files/logs. Relative paths
// use baseDir (the deployed executable directory), except state_file uses
// output_dir and existence.files use existence.base_dir.
func ParseConfig(data []byte, baseDir string) (Config, error) {
	c, err := decodeYAML(data)
	if err != nil {
		return c, err
	}
	if strings.TrimSpace(baseDir) == "" {
		return c, fmt.Errorf("configuration base directory cannot be empty")
	}
	baseDir, err = filepath.Abs(baseDir)
	if err != nil {
		return c, err
	}
	return normalizeConfig(c, baseDir, nativePathRules())
}

// ValidateEmbeddedYAML uses target-OS semantics without filesystem access or
// rewriting raw YAML. ParseConfig rechecks actual deployment paths at runtime.
func ValidateEmbeddedYAML(data []byte, targetOS string) error {
	c, err := decodeYAML(data)
	if err != nil {
		return err
	}
	if targetOS != "linux" && targetOS != "windows" {
		return fmt.Errorf("unsupported target OS %q (use linux or windows)", targetOS)
	}
	base := "/__anqu_executable__"
	if targetOS == "windows" {
		base = "C:/__anqu_executable__"
	}
	_, err = normalizeConfig(c, base, targetPathRules(targetOS == "windows"))
	return err
}

type pathRules struct {
	resolve func(base, p string) (string, error)
	isAbs   func(p string) bool
	inside  func(root, p string) bool
	key     func(p string) string
}

func nativePathRules() pathRules {
	key := func(p string) string { return p }
	if runtime.GOOS == "windows" {
		key = strings.ToLower
	}
	return pathRules{
		resolve: func(base, p string) (string, error) {
			if strings.ContainsRune(p, 0) {
				return "", fmt.Errorf("path cannot contain a NUL byte")
			}
			if runtime.GOOS == "windows" && !filepath.IsAbs(p) && (filepath.VolumeName(p) != "" || strings.HasPrefix(strings.ReplaceAll(p, "\\", "/"), "/")) {
				return "", fmt.Errorf("Windows path must be fully absolute or relative: %q", p)
			}
			return resolve(base, p), nil
		},
		isAbs: filepath.IsAbs, inside: inside, key: key,
	}
}

// filepath describes the build host, so cross-compilation validation uses
// target path rules instead: Linux /etc stays absolute on a Windows builder.
func targetPathRules(windows bool) pathRules {
	canonical := func(p string) string {
		if windows {
			p = strings.ReplaceAll(p, "\\", "/")
		}
		return p
	}
	isAbs := func(p string) bool { return strings.HasPrefix(p, "/") }
	if windows {
		isAbs = func(p string) bool {
			p = canonical(p)
			return (len(p) >= 3 && isDriveLetter(p[0]) && p[1:3] == ":/") || validUNC(p)
		}
	}
	key := func(p string) string { return p }
	if windows {
		key = strings.ToLower
	}
	clean := func(p string) string {
		p = canonical(p)
		if windows && strings.HasPrefix(p, "//") {
			parts := strings.Split(strings.TrimPrefix(p, "//"), "/")
			if len(parts) >= 2 {
				return "//" + parts[0] + "/" + parts[1] + strings.TrimSuffix(path.Clean("/"+strings.Join(parts[2:], "/")), "/")
			}
		}
		if windows && len(p) >= 3 && p[1:3] == ":/" {
			return p[:2] + path.Clean(p[2:])
		}
		return path.Clean(p)
	}
	return pathRules{
		resolve: func(base, p string) (string, error) {
			p = canonical(p)
			if strings.ContainsRune(p, 0) {
				return "", fmt.Errorf("path cannot contain a NUL byte")
			}
			if windows && !isAbs(p) && (strings.HasPrefix(p, "/") || strings.Contains(p, ":")) {
				return "", fmt.Errorf("Windows path must be fully absolute or relative: %q", p)
			}
			if isAbs(p) {
				return clean(p), nil
			}
			return clean(base + "/" + p), nil
		},
		isAbs: isAbs,
		inside: func(root, p string) bool {
			root, p = key(clean(root)), key(clean(p))
			return root == p || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
		},
		key: key,
	}
}

func isDriveLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func validUNC(p string) bool {
	if !strings.HasPrefix(p, "//") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(p, "//"), "/")
	return len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[0] != "." && parts[0] != "?"
}

func normalizeConfig(c Config, base string, rules pathRules) (Config, error) {
	resolveField := func(field, base string, p *string) error {
		if strings.TrimSpace(*p) == "" {
			return fmt.Errorf("%s cannot be empty", field)
		}
		resolved, err := rules.resolve(base, *p)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		*p = resolved
		return nil
	}
	if err := resolveField("output_dir", base, &c.OutputDir); err != nil {
		return c, err
	}
	if err := resolveField("state_file", c.OutputDir, &c.StateFile); err != nil {
		return c, err
	}
	var err error
	c.location, err = time.LoadLocation(c.Timezone)
	if err != nil {
		return c, fmt.Errorf("timezone: %w", err)
	}
	if c.MD5.Enabled {
		if len(c.MD5.Paths) == 0 {
			return c, fmt.Errorf("md5.paths cannot be empty when enabled")
		}
		for _, group := range []struct {
			name  string
			paths []string
		}{{"md5.paths", c.MD5.Paths}, {"md5.exclude_paths", c.MD5.ExcludePaths}} {
			seen := map[string]bool{}
			for i := range group.paths {
				if err := resolveField(group.name, base, &group.paths[i]); err != nil {
					return c, err
				}
				key := rules.key(group.paths[i])
				if seen[key] {
					return c, fmt.Errorf("duplicate %s entry: %s", group.name, group.paths[i])
				}
				seen[key] = true
			}
		}
		c.MD5.Paths = uniqueSorted(c.MD5.Paths)
		c.MD5.ExcludePaths = uniqueSorted(c.MD5.ExcludePaths)
		for _, p := range c.MD5.Paths {
			excluded := rules.inside(c.OutputDir, p) || rules.key(p) == rules.key(c.StateFile) || rules.inside(c.StateFile+".lock", p)
			for _, exclude := range c.MD5.ExcludePaths {
				excluded = excluded || rules.inside(exclude, p)
			}
			if excluded {
				return c, fmt.Errorf("MD5 root %s is excluded (including output/state paths)", p)
			}
		}
	}
	if c.Login.Enabled {
		if c.Login.Source != "wtmp" && c.Login.Source != "jsonl" {
			return c, fmt.Errorf("login.source must be wtmp or jsonl")
		}
		if err := resolveField("login.path", base, &c.Login.Path); err != nil {
			return c, err
		}
		if strings.TrimSpace(c.Login.LastCommand) == "" || c.Login.TimeoutSeconds < 1 || c.Login.TimeoutSeconds > 3600 || c.Login.MaxRecords < 1 || c.Login.MaxRecords > 100000 {
			return c, fmt.Errorf("invalid login command, timeout_seconds (1..3600) or max_records (1..100000)")
		}
		// A bare executable uses PATH; an explicit relative command uses baseDir.
		if strings.ContainsAny(c.Login.LastCommand, "/\\") {
			if err := resolveField("login.last_command", base, &c.Login.LastCommand); err != nil {
				return c, err
			}
		}
	}
	if c.Existence.Enabled {
		if err := resolveField("existence.base_dir", base, &c.Existence.BaseDir); err != nil {
			return c, err
		}
		if _, err := validateChecks(c.Existence, rules); err != nil {
			return c, err
		}
	}
	return c, nil
}

func loadChecks(c ExistenceConfig) ([]CheckEntry, error) { return validateChecks(c, nativePathRules()) }

func validateChecks(c ExistenceConfig, rules pathRules) ([]CheckEntry, error) {
	// Copy the inline list; validation must not mutate configured relative paths.
	entries := append([]CheckEntry(nil), c.Files...)
	if len(entries) == 0 {
		return nil, fmt.Errorf("existence.files must contain at least one path")
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
		p, err := rules.resolve(c.BaseDir, e.Path)
		if err != nil {
			return nil, err
		}
		if !rules.isAbs(e.Path) && !rules.inside(c.BaseDir, p) {
			return nil, fmt.Errorf("relative check path %q escapes base_dir; use an explicit absolute path", e.Path)
		}
		e.Path = p
		key := rules.key(e.Path)
		if seen[key] {
			return nil, fmt.Errorf("duplicate existence path %s", e.Path)
		}
		seen[key] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// readJSON reads internal reports/baselines only, never user configuration.
func readJSON(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
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
