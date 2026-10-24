package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	maxAuditRulesBytes = 8 * 1024 * 1024
	// Config permits 512 watch paths, 512 custom rules and two built-in rules.
	maxAuditRuleCount = 1026
)

var errCronAuditPathDisappeared = errors.New("optional cron audit path disappeared during rule loading")

// auditRuleLines retains each complete rule, including quotes and internal
// whitespace. Passing a rule through argv tokenization can change auditctl's
// interpretation of quoted field values, so each rule is loaded with -R.
func auditRuleLines(raw string) []string {
	seen := map[string]bool{}
	var rules []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		rules = append(rules, line)
	}
	return rules
}

// Only rule qualifiers are allowed after the initial additive operation. In
// particular a line must not combine an add with a global or delete operation.
// This validation never rewrites the rule passed to auditctl.
var auditRuleOptions = regexp.MustCompile(`(?:^|[\t ])-[A-Za-z-]`)

func validateAuditRuntimeRule(rule string) error {
	if rule != strings.TrimSpace(rule) || len(rule) > 4096 || strings.ContainsAny(rule, "\r\n\x00") {
		return errors.New("audit runtime rule must be a single additive rule of at most 4096 bytes")
	}
	var rest string
	switch {
	case strings.HasPrefix(rule, "-a always,exit "):
		rest = strings.TrimPrefix(rule, "-a always,exit ")
	case strings.HasPrefix(rule, "-w /"):
		rest = strings.TrimPrefix(rule, "-w ")
	default:
		return errors.New("audit runtime rule must start with -a always,exit or -w /")
	}
	for _, option := range auditRuleOptions.FindAllString(rest, -1) {
		option = strings.TrimSpace(option)
		switch option {
		case "-F", "-S", "-C", "-k", "-p":
		default:
			return fmt.Errorf("audit runtime rule contains unsupported operation %q", option)
		}
	}
	return nil
}

// reconcileAudit tracks only rules successfully added by this agent. A rule
// already present in the kernel is usable but does not become agent-owned.
// load=false removes owned rules without loading a preserved reference file.
func (m *Manager) reconcileAudit(ctx context.Context, current map[string]bool, save func() error, load ...bool) error {
	if current == nil {
		return errors.New("audit runtime ownership map must be initialized")
	}
	var targetRules []string
	if len(load) == 0 || load[0] {
		file, err := os.Open(m.path(auditRulesPath))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			info, statErr := file.Stat()
			if statErr != nil {
				file.Close()
				return statErr
			}
			if !info.Mode().IsRegular() || info.Size() > maxAuditRulesBytes {
				file.Close()
				return errors.New("audit rules file must be regular and at most 8 MiB")
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxAuditRulesBytes+1))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if len(data) > maxAuditRulesBytes {
				return errors.New("audit rules file exceeds 8 MiB")
			}
			targetRules = auditRuleLines(string(data))
		}
	}
	if len(targetRules) > maxAuditRuleCount || len(current) > maxAuditRuleCount {
		return fmt.Errorf("audit runtime rule count exceeds %d", maxAuditRuleCount)
	}
	target := make(map[string]bool, len(targetRules))
	available := targetRules[:0]
	for _, rule := range targetRules {
		if err := validateAuditRuntimeRule(rule); err != nil {
			return err
		}
		if path := cronAuditRulePath(rule); path != "" {
			if _, err := os.Stat(m.path(path)); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("inspect cron audit watch %s: %w", path, err)
			}
		}
		target[rule] = true
		available = append(available, rule)
	}
	targetRules = available
	for rule, owned := range current {
		if owned {
			if err := validateAuditRuntimeRule(rule); err != nil {
				return fmt.Errorf("invalid owned audit rule: %w", err)
			}
		}
	}
	persist := func() error {
		if save != nil {
			return save()
		}
		return nil
	}
	for _, rule := range sortedKeys(current) {
		if !current[rule] || target[rule] {
			continue
		}
		deleteRule := "-d" + strings.TrimPrefix(rule, "-a")
		if strings.HasPrefix(rule, "-w ") {
			deleteRule = "-W" + strings.TrimPrefix(rule, "-w")
		}
		if _, err := m.runAuditRule(ctx, deleteRule, false); err != nil {
			return fmt.Errorf("remove audit rule %q: %w", rule, err)
		}
		delete(current, rule)
		if err := persist(); err != nil {
			return err
		}
	}
	for _, rule := range targetRules {
		existed, err := m.runAuditRule(ctx, rule, true)
		if errors.Is(err, errCronAuditPathDisappeared) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load audit rule %q: %w", rule, err)
		}
		if !existed && !current[rule] {
			current[rule] = true
			if err := persist(); err != nil {
				return err
			}
		}
	}
	// A command may finish successfully just as its context is canceled. Its
	// ownership change must be saved before returning cancellation so rollback
	// can undo every rule the kernel actually accepted.
	return ctx.Err()
}

func (m *Manager) runAuditRule(ctx context.Context, rule string, add bool) (alreadyPresent bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.MkdirAll(m.OutputDir, 0700); err != nil {
		return false, err
	}
	file, err := os.CreateTemp(m.OutputDir, ".anquan-audit-rule-*")
	if err != nil {
		return false, err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.WriteString(rule + "\n")
	}
	closeErr := file.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	out, err := m.Runner.Run(ctx, "auditctl", "-R", name)
	if err == nil {
		return false, nil
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return false, contextErr
	}
	want := "Error sending delete rule data request (No such file or directory)"
	if add {
		want = "Error sending add rule data request (Rule exists)"
	}
	if auditRuleExpectedKernelError(out, want, name) {
		return add, nil
	}
	if !add && auditRuleExpectedKernelError(out, "Error sending delete rule request (No rule matches)", name) {
		return false, nil
	}
	if add && cronAuditRulePath(rule) != "" && auditRuleExpectedKernelError(out, "Error sending add rule data request (No such file or directory)", name) {
		// Ignore only a verified disappearance and its exact kernel error.
		// Permission failures and extra diagnostics must still reject Apply.
		if _, statErr := os.Stat(m.path(cronAuditRulePath(rule))); os.IsNotExist(statErr) {
			return false, errCronAuditPathDisappeared
		} else if statErr != nil {
			return false, statErr
		}
	}
	return false, err
}

// Match stdout/stderr from the one-rule invocation, never the Runner's wrapped
// error text. Any additional diagnostic makes the failure non-ignorable.
func auditRuleExpectedKernelError(out, want, file string) bool {
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "":
		case want:
			if found {
				return false
			}
			found = true
		case "There was an error in line 1 of " + file:
		default:
			return false
		}
	}
	return found
}
