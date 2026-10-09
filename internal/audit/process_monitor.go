package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Each exists entry is a group of alternative, complete command lines.
// Process presence enables rolling inventory comparisons; whitelist entries
// suppress inventory change alerts without suppressing required-process checks.
type ProcessMonitoringConfig struct {
	Exists  []string           `json:"exists" yaml:"exists"`
	Process *ProcessListConfig `json:"Process,omitempty" yaml:"Process"`
}

type ProcessListConfig struct {
	Whitelist []string `json:"whitelist" yaml:"whitelist"`
}

type ProcessExistsResult struct {
	Rule         string   `json:"rule"`
	Alternatives []string `json:"alternatives"`
	Matched      []string `json:"matched"`
	Exists       bool     `json:"exists"`
}

type ProcessInventoryItem struct {
	Command     string `json:"command"`
	Count       int    `json:"count"`
	Whitelisted bool   `json:"whitelisted"`
}

type ProcessChange struct {
	Command string `json:"command"`
	Kind    string `json:"kind"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
}

type ProcessResult struct {
	Enabled         bool                   `json:"enabled"`
	Success         bool                   `json:"success"`
	BaselineCreated bool                   `json:"baseline_created"`
	Scanned         int                    `json:"scanned"`
	Missing         int                    `json:"missing"`
	Items           []ProcessExistsResult  `json:"items"`
	Inventory       []ProcessInventoryItem `json:"inventory"`
	Changes         []ProcessChange        `json:"changes"`
	Alerts          []Alert                `json:"alerts"`
}

type processBaseline struct {
	Version   int            `json:"version"`
	Scope     string         `json:"scope"`
	UpdatedAt time.Time      `json:"updated_at"`
	Processes map[string]int `json:"processes"`
}

func normalizeProcessMonitoring(c *ProcessMonitoringConfig) error {
	if c == nil {
		return nil
	}
	if len(c.Exists) == 0 && c.Process == nil {
		return fmt.Errorf("ProcessMonitoring requires exists or Process")
	}
	seen := map[string]bool{}
	for i, raw := range c.Exists {
		alternatives, err := processAlternatives(raw)
		if err != nil {
			return fmt.Errorf("ProcessMonitoring.exists[%d]: %w", i, err)
		}
		rule := strings.Join(alternatives, "|")
		if seen[rule] {
			return fmt.Errorf("duplicate ProcessMonitoring.exists rule: %s", rule)
		}
		seen[rule] = true
		c.Exists[i] = rule
	}
	if c.Process != nil {
		var whitelist []string
		for i, raw := range c.Process.Whitelist {
			alternatives, err := processAlternatives(raw)
			if err != nil {
				return fmt.Errorf("ProcessMonitoring.Process.whitelist[%d]: %w", i, err)
			}
			whitelist = append(whitelist, alternatives...)
		}
		c.Process.Whitelist = uniqueSorted(whitelist)
	}
	return nil
}

func processAlternatives(raw string) ([]string, error) {
	if strings.ContainsRune(raw, 0) || strings.ContainsAny(raw, "\r\n") {
		return nil, fmt.Errorf("command must be a single line without NUL bytes")
	}
	parts := strings.Split(raw, "|")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 0 && (part[0] == '\'' || part[0] == '"') {
			if len(part) < 2 || part[len(part)-1] != part[0] {
				return nil, fmt.Errorf("unclosed outer quote in command %q", part)
			}
			part = part[1 : len(part)-1]
		}
		parts[i] = normalizeProcessCommand(part)
		if parts[i] == "" {
			return nil, fmt.Errorf("command alternatives cannot be empty")
		}
	}
	return uniqueSorted(parts), nil
}

// /proc represents argument boundaries with NUL bytes. Commands are compared as
// entire whitespace-normalized display lines, never by substring or executable
// basename, so e.g. /usr/sbin/sshd -D-extra cannot satisfy /usr/sbin/sshd -D.
func normalizeProcessCommand(command string) string {
	return strings.Join(strings.Fields(command), " ")
}

func processScope(c *ProcessListConfig) string {
	data, _ := json.Marshal(uniqueSorted(c.Whitelist))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func collectProcessMonitoring(c Config, now time.Time) (ProcessResult, *processBaseline, []Issue) {
	return collectProcessMonitoringWithScanner(c, now, scanSystemProcesses)
}

func collectProcessMonitoringWithScanner(c Config, now time.Time, scan func() (map[string]int, error)) (ProcessResult, *processBaseline, []Issue) {
	r := ProcessResult{Enabled: c.ProcessMonitoring != nil, Success: true, Items: []ProcessExistsResult{}, Inventory: []ProcessInventoryItem{}, Changes: []ProcessChange{}, Alerts: []Alert{}}
	if !r.Enabled {
		return r, nil, nil
	}
	fail := func(message string) (ProcessResult, *processBaseline, []Issue) {
		r.Success = false
		return r, nil, []Issue{{Module: "processes", Message: message}}
	}
	// A failed or incomplete collection must never produce false missing/deleted
	// alerts or replace the last complete baseline.
	observed, err := scan()
	if err != nil {
		return fail("scan processes: " + err.Error())
	}
	counts := make(map[string]int, len(observed))
	for command, count := range observed {
		command = normalizeProcessCommand(command)
		if command == "" || count < 1 {
			return fail("scan returned an invalid command/count")
		}
		counts[command] += count
	}
	whitelist := map[string]bool{}
	if c.ProcessMonitoring.Process != nil {
		for _, command := range c.ProcessMonitoring.Process.Whitelist {
			whitelist[command] = true
		}
	}
	current := map[string]int{}
	for command, count := range counts {
		r.Scanned += count
		r.Inventory = append(r.Inventory, ProcessInventoryItem{Command: command, Count: count, Whitelisted: whitelist[command]})
		if !whitelist[command] {
			current[command] = count
		}
	}
	sort.Slice(r.Inventory, func(i, j int) bool { return r.Inventory[i].Command < r.Inventory[j].Command })
	for _, rule := range c.ProcessMonitoring.Exists {
		alternatives, err := processAlternatives(rule)
		if err != nil {
			return fail("invalid exists rule: " + err.Error())
		}
		item := ProcessExistsResult{Rule: rule, Alternatives: alternatives, Matched: []string{}}
		for _, command := range alternatives {
			if counts[command] > 0 {
				item.Matched = append(item.Matched, command)
			}
		}
		item.Exists = len(item.Matched) > 0
		if !item.Exists {
			r.Missing++
			r.Alerts = append(r.Alerts, Alert{Module: "processes", Kind: "missing", Target: rule, Message: "none of the required command alternatives is running"})
		}
		r.Items = append(r.Items, item)
	}
	if c.ProcessMonitoring.Process == nil {
		return r, nil, nil
	}
	var old processBaseline
	err = readBaseline(c, c.StateFile+".processes", "processes", &old)
	first := os.IsNotExist(err)
	if err != nil && !first {
		return fail("read process baseline: " + err.Error())
	}
	scope := processScope(c.ProcessMonitoring.Process)
	if !first {
		if old.Version != 1 || old.Processes == nil || old.Scope != scope || old.UpdatedAt.IsZero() {
			return fail("process baseline is invalid or whitelist changed; move the old .processes state file aside to explicitly initialize a new baseline")
		}
		for command, count := range old.Processes {
			if command == "" || command != normalizeProcessCommand(command) || count < 1 || whitelist[command] {
				return fail("invalid command/count in process baseline")
			}
		}
		commands := map[string]bool{}
		for command := range old.Processes {
			commands[command] = true
		}
		for command := range current {
			commands[command] = true
		}
		for command := range commands {
			before, after := old.Processes[command], current[command]
			if before == after {
				continue
			}
			kind := "added"
			if after < before {
				kind = "deleted"
			}
			r.Changes = append(r.Changes, ProcessChange{Command: command, Kind: kind, Before: before, After: after})
		}
		sort.Slice(r.Changes, func(i, j int) bool { return r.Changes[i].Command < r.Changes[j].Command })
		for _, change := range r.Changes {
			r.Alerts = append(r.Alerts, Alert{Module: "processes", Kind: change.Kind, Target: change.Command, Before: strconv.Itoa(change.Before), After: strconv.Itoa(change.After), Message: fmt.Sprintf("running instance count changed from %d to %d", change.Before, change.After)})
		}
	}
	r.BaselineCreated = first
	return r, &processBaseline{Version: 1, Scope: scope, UpdatedAt: now, Processes: current}, nil
}

// Kept platform independent so the Linux /proc reader can be exercised against
// fixtures on builders of any OS. No ps/shell helper is launched during a scan.
func scanProcProcesses(root string, selfPID int) (map[string]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 || pid == selfPID || !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		data, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			if processDisappeared(dir, err) {
				continue
			}
			return nil, fmt.Errorf("read process %d cmdline: %w", pid, err)
		}
		command := normalizeProcessCommand(strings.ReplaceAll(string(data), "\x00", " "))
		if command == "" {
			// Kernel threads and zombies have no argv. Preserve their names as
			// bracketed commands instead of silently omitting them from inventory.
			data, err = os.ReadFile(filepath.Join(dir, "comm"))
			if err != nil {
				if processDisappeared(dir, err) {
					continue
				}
				return nil, fmt.Errorf("read process %d comm: %w", pid, err)
			}
			name := normalizeProcessCommand(string(data))
			if name == "" {
				return nil, fmt.Errorf("process %d has empty cmdline and comm", pid)
			}
			command = "[" + name + "]"
		}
		counts[command]++
	}
	return counts, nil
}

func processDisappeared(dir string, readErr error) bool {
	if !os.IsNotExist(readErr) {
		return false
	}
	_, err := os.Stat(dir)
	return os.IsNotExist(err)
}
