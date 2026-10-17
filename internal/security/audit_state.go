package security

import (
	"errors"
	"io"
	"os"
)

// A legacy key is not enough evidence to delete a running rule. An exact,
// owned rules file can recover the old complete specifications before it is
// changed. Referenced, missing or drifted files never grant runtime ownership.
func (m *Manager) trackLegacyAuditRules(state *manifest) error {
	// Do not carry broad key-based cleanup instructions into new state.
	state.AuditKeys = nil
	if state.AuditRulesTracked {
		if state.AuditRules == nil {
			state.AuditRules = map[string]bool{}
		}
		return nil
	}
	state.AuditRules = map[string]bool{}
	state.AuditRulesTracked = true
	want := state.Files[auditRulesPath]
	if want == "" {
		return nil
	}
	path := m.path(auditRulesPath)
	if err := noSymlink(path); err != nil {
		return err
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxAuditRulesBytes {
		return errors.New("legacy audit rules file must be regular and at most 8 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuditRulesBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxAuditRulesBytes {
		return errors.New("legacy audit rules file exceeds 8 MiB")
	}
	if hashString(string(data)) != want {
		return nil
	}
	for _, rule := range auditRuleLines(string(data)) {
		if err := validateAuditRuntimeRule(rule); err != nil {
			return err
		}
		state.AuditRules[rule] = true
	}
	return nil
}
