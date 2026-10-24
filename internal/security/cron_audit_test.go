package security

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const cronTableAuditRule = "-w /etc/crontab -p wa -k anquan_file"
const cronDirectoryAuditRule = "-w /etc/cron.d -p wa -k anquan_file"

func TestCronAuditMissingAppearDeleteAndRecreate(t *testing.T) {
	m, r := runtimeAuditManager(t)
	m.Config.Auditd.WatchPaths = DefaultCronPaths()
	m.Config.Policies = PolicyConfig{Mode: "audit", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}, SessionTimeoutSeconds: 900, DisableCtrlAltDel: true}
	r.values["kernel.kptr_restrict"] = "0"
	r.rules[runtimeAdminRule] = true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("absent standard cron roots blocked initialization: %v", err)
	}
	for _, path := range DefaultCronPaths() {
		if _, err := os.Lstat(m.path(path)); !os.IsNotExist(err) {
			t.Fatalf("initialization created an optional cron target %s: %v", path, err)
		}
	}
	requireRuntimeRules(t, r, runtimeAdminRule)
	requireAuditOwnership(t, m)
	put(t, m, "/etc/crontab", []byte("# first crontab\n"))
	if err := os.MkdirAll(m.path("/etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatalf("audit-mode cron reconciliation did not attach new roots: %v", err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule, cronTableAuditRule, cronDirectoryAuditRule)
	requireAuditOwnership(t, m, cronTableAuditRule, cronDirectoryAuditRule)
	if err := os.Remove(m.path("/etc/crontab")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.path("/etc/cron.d")); err != nil {
		t.Fatal(err)
	}
	// File watches may remain attached to their parent while an evicted audit
	// directory tree is removed by the kernel. Reconcile must handle both.
	delete(r.rules, cronDirectoryAuditRule)
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatalf("deleted cron roots did not return to waiting: %v", err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule)
	requireAuditOwnership(t, m)
	raw, err := os.ReadFile(m.path(auditRulesPath))
	if err != nil || strings.Contains(string(raw), "-w ") {
		t.Fatalf("persisted rules still contain absent cron roots: %q %v", raw, err)
	}
	put(t, m, "/etc/crontab", []byte("# recreated crontab\n"))
	if err := os.Mkdir(m.path("/etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatalf("recreated cron roots were not watched again: %v", err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule, cronTableAuditRule, cronDirectoryAuditRule)
	requireAuditOwnership(t, m, cronTableAuditRule, cronDirectoryAuditRule)
	for _, path := range []string{sysctlConfigPath, sessionConfigPath, ctrlAltDelConfigPath} {
		if _, err := os.Stat(m.path(path)); !os.IsNotExist(err) {
			t.Fatalf("audit-mode reconciliation wrote an enforce-only host policy %s: %v", path, err)
		}
	}
	if r.values["kernel.kptr_restrict"] != "0" {
		t.Fatal("audit-mode cron reconciliation changed a runtime sysctl")
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "auditctl -D") || strings.HasPrefix(call, "auditctl -e") || strings.HasPrefix(call, "auditctl -f") {
			t.Fatalf("cron reconciliation changed global audit policy: %s", call)
		}
	}
}

func TestCronAuditReloadsKernelWatchWhenRuleFileIsUnchanged(t *testing.T) {
	m, r := runtimeAuditManager(t)
	m.Config.Auditd.WatchPaths = []string{"/etc/cron.d"}
	if err := os.MkdirAll(m.path("/etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(m.path(auditRulesPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.path("/etc/cron.d")); err != nil {
		t.Fatal(err)
	}
	delete(r.rules, cronDirectoryAuditRule) // The kernel evicted the old inode.
	if err := os.Mkdir(m.path("/etc/cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, cronDirectoryAuditRule)
	after, err := os.ReadFile(m.path(auditRulesPath))
	if err != nil || string(before) != string(after) {
		t.Fatalf("unchanged rule file fixture changed: %v", err)
	}
	operations := len(r.operations)
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, operation := range r.operations[operations:] {
		if strings.HasPrefix(operation, "-W ") || strings.HasPrefix(operation, "-d ") {
			t.Fatal("healthy periodic reconciliation removed a live watch before reloading")
		}
	}
}

func TestCronAuditDoesNotOwnOrRemovePreexistingRules(t *testing.T) {
	m, r := runtimeAuditManager(t)
	m.Config.Auditd.WatchPaths = []string{"/etc/crontab"}
	put(t, m, "/etc/crontab", []byte("# administrator crontab\n"))
	r.rules[cronTableAuditRule], r.rules[runtimeAdminRule] = true, true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireAuditOwnership(t, m)
	if err := os.Remove(m.path("/etc/crontab")); err != nil {
		t.Fatal(err)
	}
	operations := len(r.operations)
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule, cronTableAuditRule)
	for _, operation := range r.operations[operations:] {
		if strings.HasPrefix(operation, "-W ") || strings.HasPrefix(operation, "-d ") {
			t.Fatalf("missing optional root deleted an unowned administrator rule: %s", operation)
		}
	}
}

func TestCronAuditMissingNonstandardPathStillRejectsApply(t *testing.T) {
	for _, path := range []string{"/etc/required-file", "/etc/cron.custom", "/etc/cron.d/required-job"} {
		t.Run(path, func(t *testing.T) {
			m, r := runtimeAuditManager(t)
			m.Config.Auditd.WatchPaths = append(DefaultCronPaths(), path)
			r.rules[runtimeAdminRule] = true
			if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("explicit nonstandard missing path was silently optional: %v", err)
			}
			requireRuntimeRules(t, r, runtimeAdminRule)
			if _, err := os.Stat(m.manifestPath()); !os.IsNotExist(err) {
				t.Fatalf("rejected path committed a manifest: %v", err)
			}
		})
	}
}

func TestCronAuditLoadRaceIgnoresOnlyVerifiedMissingPath(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		wantSuccess      bool
	}{
		{"disappeared", "Error sending add rule data request (No such file or directory)", true},
		{"permission", "Error sending add rule data request (Operation not permitted)", false},
		{"extra_permission_diagnostic", "Error sending add rule data request (No such file or directory)\nPermission denied", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r := runtimeAuditManager(t)
			m.Config.Auditd.WatchPaths = []string{"/etc/crontab"}
			put(t, m, "/etc/crontab", []byte("# disappears while loading\n"))
			r.rules[runtimeAdminRule] = true
			failed := false
			r.failRule = func(rule string) (string, error) {
				if rule != cronTableAuditRule || failed {
					return "", nil
				}
				failed = true
				if err := os.Remove(m.path("/etc/crontab")); err != nil {
					t.Fatal(err)
				}
				return tc.diagnostic, errors.New("exit status 1")
			}
			_, err := m.Apply(context.Background())
			if !failed || (err == nil) != tc.wantSuccess {
				t.Fatalf("load race success=%t, want=%t: %v", err == nil, tc.wantSuccess, err)
			}
			requireRuntimeRules(t, r, runtimeAdminRule)
			if tc.wantSuccess {
				if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
					t.Fatal(err)
				}
				put(t, m, "/etc/crontab", []byte("# appeared after the race\n"))
				if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
					t.Fatal(err)
				}
				requireRuntimeRules(t, r, runtimeAdminRule, cronTableAuditRule)
			}
		})
	}
}

func TestCronAuditAcceptsExactModernMissingDeleteResponse(t *testing.T) {
	for _, extra := range []bool{false, true} {
		m, r := runtimeAuditManager(t)
		m.Config.Auditd.WatchPaths = []string{"/etc/crontab"}
		put(t, m, "/etc/crontab", []byte("# crontab\n"))
		if _, err := m.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(m.path("/etc/crontab")); err != nil {
			t.Fatal(err)
		}
		delete(r.rules, cronTableAuditRule)
		r.failRule = func(rule string) (string, error) {
			if !strings.HasPrefix(rule, "-W ") {
				return "", nil
			}
			out := "Error sending delete rule request (No rule matches)"
			if extra {
				out += "\nOperation not permitted"
			}
			return out, errors.New("exit status 1")
		}
		err := m.reconcileEnforcedPolicies(context.Background())
		if (err != nil) != extra {
			t.Fatalf("modern missing delete error additional_diagnostic=%t: %v", extra, err)
		}
	}
}
