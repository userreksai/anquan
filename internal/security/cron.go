package security

import "strings"

var standardCronPaths = []string{
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/cron.allow",
	"/etc/cron.deny",
	"/var/spool/cron",
	"/etc/anacrontab",
	"/etc/cron.yearly",
}

// DefaultCronPaths returns independent storage so callers can extend their
// monitored paths without changing the standard optional cron roots.
func DefaultCronPaths() []string { return append([]string(nil), standardCronPaths...) }

// IsCronPath is deliberately an exact allowlist. A typo, an arbitrary /etc
// path, or an explicitly selected cron job must retain missing-path errors.
func IsCronPath(path string) bool {
	for _, candidate := range standardCronPaths {
		if path == candidate {
			return true
		}
	}
	return false
}

func (m *Manager) hasCronAuditWatches() bool {
	if !m.Config.Enabled || !m.Config.Auditd.Enabled {
		return false
	}
	for _, path := range m.Config.Auditd.WatchPaths {
		if IsCronPath(path) {
			return true
		}
	}
	return false
}

// Only the generated write/attribute rule receives optional-path treatment;
// custom rules with additional predicates retain their original semantics.
func cronAuditRulePath(rule string) string {
	if !strings.HasPrefix(rule, "-w ") || !strings.HasSuffix(rule, " -p wa -k anquan_file") {
		return ""
	}
	path := strings.TrimSuffix(strings.TrimPrefix(rule, "-w "), " -p wa -k anquan_file")
	if IsCronPath(path) {
		return path
	}
	return ""
}
