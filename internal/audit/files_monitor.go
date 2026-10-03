package audit

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fils retains the spelling in the deployed configuration format.
type FilesMonitoringConfig struct {
	Fils   []string `json:"fils" yaml:"fils"`
	Dir    []string `json:"dir" yaml:"dir"`
	Search []string `json:"search" yaml:"search"`
	rules  []filesMonitoringRule
}

type filesMonitoringRule struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name,omitempty"`
	Paths  []string `json:"paths"`
	Hashes []string `json:"hashes"`
}

type FileCheckResult struct {
	Path        string   `json:"path"`
	Rule        string   `json:"rule"`
	Mode        string   `json:"mode"`
	Status      string   `json:"status"`
	MD5         string   `json:"md5,omitempty"`
	ExpectedMD5 []string `json:"expected_md5,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type FilesResult struct {
	Enabled         bool              `json:"enabled"`
	Success         bool              `json:"success"`
	BaselineCreated bool              `json:"baseline_created"`
	Scanned         int               `json:"scanned"`
	Skipped         int               `json:"skipped_non_regular"`
	MissingRoots    []string          `json:"missing_roots"`
	Rules           []FileRuleResult  `json:"rules"`
	Items           []FileCheckResult `json:"items"`
	Changes         []Change          `json:"changes"`
	Alerts          []Alert           `json:"alerts"`
}

// Each rule reports its own allowlist totals so a partially matched multi-path
// entry remains visible even when other rules succeed.
type FileRuleResult struct {
	Rule         string   `json:"rule"`
	Paths        []string `json:"paths"`
	Mode         string   `json:"mode"`
	Scanned      int      `json:"scanned"`
	Matched      int      `json:"matched"`
	Mismatched   int      `json:"mismatched"`
	MissingRoots int      `json:"missing_roots"`
}

type filesBaseline struct {
	Version   int               `json:"version"`
	Scope     string            `json:"scope"`
	UpdatedAt time.Time         `json:"updated_at"`
	Files     map[string]string `json:"files"`
}

func normalizeFilesMonitoring(c *FilesMonitoringConfig, base string, paths pathRules) error {
	if c == nil {
		return nil
	}
	c.rules = nil
	seenRoots := map[string]bool{}
	seenSearch := map[string]bool{}
	for _, group := range []struct {
		kind    string
		entries []string
	}{{"fils", c.Fils}, {"dir", c.Dir}, {"search", c.Search}} {
		for _, entry := range group.entries {
			parts := strings.Split(entry, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
				if parts[i] == "" {
					return fmt.Errorf("FilesMonitoring.%s contains an empty path/name/MD5 in %q", group.kind, entry)
				}
			}
			rule := filesMonitoringRule{Kind: group.kind, Paths: []string{}, Hashes: []string{}}
			pathsIndex := 0
			if group.kind == "search" {
				if len(parts) < 2 || strings.ContainsAny(parts[0], "/\\|\x00") || parts[0] == "." || parts[0] == ".." {
					return fmt.Errorf("FilesMonitoring.search requires filename,path1|path2[,MD5...]: %q", entry)
				}
				rule.Name, pathsIndex = parts[0], 1
			}
			seenPaths := map[string]bool{}
			for _, raw := range strings.Split(parts[pathsIndex], "|") {
				raw = strings.TrimSpace(raw)
				if raw == "" {
					return fmt.Errorf("FilesMonitoring.%s contains an empty path in %q", group.kind, entry)
				}
				p, err := paths.resolve(base, raw)
				if err != nil {
					return fmt.Errorf("FilesMonitoring.%s: %w", group.kind, err)
				}
				key := paths.key(p)
				if seenPaths[key] {
					return fmt.Errorf("duplicate FilesMonitoring.%s path: %s", group.kind, p)
				}
				seenPaths[key] = true
				if group.kind == "search" {
					searchKey := paths.key(rule.Name) + "\x00" + key
					if seenSearch[searchKey] {
						return fmt.Errorf("duplicate FilesMonitoring.search filename/root: %s in %s", rule.Name, p)
					}
					seenSearch[searchKey] = true
				} else {
					if seenRoots[key] {
						return fmt.Errorf("duplicate FilesMonitoring path: %s", p)
					}
					seenRoots[key] = true
				}
				rule.Paths = append(rule.Paths, p)
			}
			seenHashes := map[string]bool{}
			for _, raw := range parts[pathsIndex+1:] {
				hash := strings.ToLower(raw)
				if !validFileMD5(hash) {
					return fmt.Errorf("FilesMonitoring.%s MD5 must contain exactly 32 hexadecimal characters: %q", group.kind, raw)
				}
				if seenHashes[hash] {
					return fmt.Errorf("duplicate FilesMonitoring.%s MD5: %s", group.kind, hash)
				}
				seenHashes[hash] = true
				rule.Hashes = append(rule.Hashes, hash)
			}
			sort.Strings(rule.Paths)
			sort.Strings(rule.Hashes)
			c.rules = append(c.rules, rule)
		}
	}
	if len(c.rules) == 0 {
		return fmt.Errorf("FilesMonitoring requires at least one fils, dir or search entry")
	}
	sort.Slice(c.rules, func(i, j int) bool {
		a, _ := json.Marshal(c.rules[i])
		b, _ := json.Marshal(c.rules[j])
		return string(a) < string(b)
	})
	return nil
}

func validFileMD5(hash string) bool {
	b, err := hex.DecodeString(hash)
	return err == nil && len(b) == md5.Size
}

func filesMonitoringScope(c Config) string {
	b, _ := json.Marshal(struct {
		Rules         []filesMonitoringRule
		Output, State string
	}{c.FilesMonitoring.rules, c.OutputDir, c.StateFile})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func collectFilesMonitoring(c Config, now time.Time) (FilesResult, *filesBaseline, []Issue) {
	r := FilesResult{Enabled: c.FilesMonitoring != nil, Success: true, MissingRoots: []string{}, Rules: []FileRuleResult{}, Items: []FileCheckResult{}, Changes: []Change{}, Alerts: []Alert{}}
	if !r.Enabled {
		return r, nil, nil
	}
	var issues []Issue
	addError := func(p, message string) {
		r.Success = false
		issues = append(issues, Issue{Module: "files", Message: p + ": " + message})
		r.Alerts = append(r.Alerts, Alert{Module: "files", Kind: "inspection_error", Target: p, Message: message})
	}
	if len(c.FilesMonitoring.rules) == 0 {
		addError("configuration", "FilesMonitoring must be normalized before collection")
		return r, nil, issues
	}
	var old filesBaseline
	err := readJSON(c.StateFile+".files", &old)
	first := os.IsNotExist(err)
	if err != nil && !first {
		addError(c.StateFile+".files", "read baseline: "+err.Error())
		return r, nil, issues
	}
	if !first {
		if old.Version != 1 || old.Files == nil || old.Scope != filesMonitoringScope(c) {
			addError(c.StateFile+".files", "baseline is invalid or monitored paths/options changed; preserve and move the state file aside explicitly to initialize a new baseline")
			return r, nil, issues
		}
		for p, hash := range old.Files {
			if !filepath.IsAbs(p) || !validFileMD5(hash) || !filesPathInScope(c, p) || monitoringExcluded(c, p) {
				addError(c.StateFile+".files", "invalid baseline path/hash: "+p)
				return r, nil, issues
			}
		}
	}
	files := map[string]string{}
	automatic := map[string]bool{}
	failed := map[string]bool{}
	skipped := map[string]bool{}
	missing := map[string]bool{}
	for _, rule := range c.FilesMonitoring.rules {
		mode := "baseline"
		if len(rule.Hashes) > 0 {
			mode = "allowlist"
		}
		ruleLabel := rule.Kind
		if rule.Name != "" {
			ruleLabel += ":" + rule.Name
		}
		ruleLabel += ":" + strings.Join(rule.Paths, "|")
		summary := FileRuleResult{Rule: ruleLabel, Paths: rule.Paths, Mode: mode}
		seenRule := map[string]bool{}
		matches := 0
		for _, root := range rule.Paths {
			if monitoringExcluded(c, root) {
				addError(root, "configured monitoring root is excluded because it is an agent output/state path")
				continue
			}
			info, statErr := os.Lstat(root)
			if os.IsNotExist(statErr) {
				summary.MissingRoots++
				if !missing[root] {
					missing[root] = true
					r.MissingRoots = append(r.MissingRoots, root)
					r.Alerts = append(r.Alerts, Alert{Module: "files", Kind: "missing", Target: root, Message: "configured file or directory does not exist"})
				}
				r.Items = append(r.Items, FileCheckResult{Path: root, Rule: ruleLabel, Mode: mode, Status: "missing", ExpectedMD5: rule.Hashes})
				// ENOENT is a known absence, not an incomplete scan. Save other
				// observed files; a missing root appearing later is an addition.
				continue
			}
			if statErr != nil {
				addError(root, statErr.Error())
				continue
			}
			if (rule.Kind == "dir" || rule.Kind == "search") && !info.IsDir() {
				addError(root, "configured dir/search root is not a directory (directory symlinks are not followed)")
				continue
			}
			walkErr := filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
				if monitoringExcluded(c, p) {
					if entry != nil && entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if err != nil {
					addError(p, err.Error())
					return nil
				}
				if entry.IsDir() {
					return nil
				}
				if rule.Kind == "search" && entry.Name() != rule.Name {
					if !entry.Type().IsRegular() && filesHadSubtree(old.Files, p) {
						addError(p, "previously monitored subtree was replaced by a symlink or special file")
					}
					return nil
				}
				if seenRule[p] {
					return nil
				}
				seenRule[p] = true
				item := FileCheckResult{Path: p, Rule: ruleLabel, Mode: mode, ExpectedMD5: rule.Hashes}
				if !entry.Type().IsRegular() {
					item.Status = "unsupported"
					item.Error = "not a regular file; symlinks and special files are not hashed"
					r.Items = append(r.Items, item)
					if !skipped[p] {
						skipped[p] = true
						r.Skipped++
					}
					// A configured path or a previously tracked file cannot silently
					// disappear from monitoring by becoming a symlink/device.
					if p == root || filesHadSubtree(old.Files, p) {
						addError(p, item.Error)
					}
					return nil
				}
				matches++
				if failed[p] {
					return nil
				}
				hash, cached := files[p]
				if !cached {
					var hashErr error
					hash, hashErr = hashFile(p)
					if hashErr != nil {
						failed[p] = true
						item.Status, item.Error = "error", hashErr.Error()
						r.Items = append(r.Items, item)
						addError(p, hashErr.Error())
						return nil
					}
					files[p] = hash
				}
				item.MD5 = hash
				summary.Scanned++
				if mode == "allowlist" {
					item.Status = "mismatch"
					for _, allowed := range rule.Hashes {
						if hash == allowed {
							item.Status = "matched"
							break
						}
					}
					if item.Status == "mismatch" {
						summary.Mismatched++
						r.Alerts = append(r.Alerts, Alert{Module: "files", Kind: "md5_mismatch", Target: p, Message: "current MD5 does not match any configured allowed value", Before: strings.Join(rule.Hashes, ","), After: hash})
					} else {
						summary.Matched++
					}
				} else {
					automatic[p] = true
					before, existed := old.Files[p]
					switch {
					case first:
						item.Status = "baseline_created"
					case !existed:
						item.Status = "added"
					case before != hash:
						item.Status = "modified"
					default:
						item.Status = "unchanged"
					}
				}
				r.Items = append(r.Items, item)
				return nil
			})
			if walkErr != nil {
				addError(root, walkErr.Error())
			}
		}
		if rule.Kind == "search" && matches == 0 {
			target := strings.Join(rule.Paths, "|") + ":" + rule.Name
			r.Items = append(r.Items, FileCheckResult{Path: target, Rule: ruleLabel, Mode: mode, Status: "not_found", ExpectedMD5: rule.Hashes})
			r.Alerts = append(r.Alerts, Alert{Module: "files", Kind: "not_found", Target: target, Message: "no regular file with the configured exact filename was found"})
		}
		r.Rules = append(r.Rules, summary)
	}
	r.Scanned = len(files)
	sort.Strings(r.MissingRoots)
	sort.SliceStable(r.Items, func(i, j int) bool { return r.Items[i].Path < r.Items[j].Path })
	if len(issues) > 0 {
		for i := range r.Items {
			if r.Items[i].Status == "baseline_created" {
				r.Items[i].Status = "baseline_pending"
			}
		}
		// Keep every previous entry when any subtree is unreadable or unstable;
		// otherwise missing scan results could be mistaken for deletions.
		return r, nil, issues
	}
	if !first {
		for p, hash := range files {
			before, existed := old.Files[p]
			if !existed {
				r.Changes = append(r.Changes, Change{Path: p, Kind: "added", After: hash})
			} else if automatic[p] && before != hash {
				r.Changes = append(r.Changes, Change{Path: p, Kind: "modified", Before: before, After: hash})
			}
		}
		for p, before := range old.Files {
			if _, exists := files[p]; !exists {
				r.Changes = append(r.Changes, Change{Path: p, Kind: "deleted", Before: before})
			}
		}
	}
	sort.Slice(r.Changes, func(i, j int) bool { return r.Changes[i].Path < r.Changes[j].Path })
	for _, change := range r.Changes {
		r.Alerts = append(r.Alerts, Alert{Module: "files", Kind: change.Kind, Target: change.Path, Message: "monitored file " + change.Kind, Before: change.Before, After: change.After})
	}
	r.BaselineCreated = first
	return r, &filesBaseline{Version: 1, Scope: filesMonitoringScope(c), UpdatedAt: now, Files: files}, nil
}

func filesPathInScope(c Config, p string) bool {
	for _, rule := range c.FilesMonitoring.rules {
		if rule.Kind == "search" && filepath.Base(p) != rule.Name {
			continue
		}
		for _, root := range rule.Paths {
			if inside(root, p) {
				return true
			}
		}
	}
	return false
}

func filesHadSubtree(files map[string]string, root string) bool {
	for p := range files {
		if inside(root, p) {
			return true
		}
	}
	return false
}
