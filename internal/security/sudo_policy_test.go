package security

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

type sudoPolicyRunner struct {
	*fakeRunner
	uid                string
	allowProbe         bool
	denyGrant          bool
	defaultsOutput     string
	incompleteDefaults bool
}

func (r *sudoPolicyRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "id" && len(args) == 2 && args[0] == "-u" {
		return r.uid, nil
	}
	if name == "sudo" {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		if len(args) == 4 && args[0] == "-n" && args[1] == "-ll" {
			if r.incompleteDefaults {
				return "(root) PASSWD: /usr/bin/systemctl", nil
			}
			if r.defaultsOutput != "" {
				return r.defaultsOutput, nil
			}
			return "Matching Defaults entries for deploy on test-host:\n    env_reset, !exempt_group\n\nUser deploy may run the following commands on test-host:\n\nSudoers entry: /etc/sudoers.d/zzzz-anquan-restrict\n    RunAsUsers: root\n    Options: authenticate, !setenv\n    Commands:\n        /usr/bin/systemctl\n", nil
		}
		if len(args) == 4 && args[0] == "-n" && args[1] == "-l" && !r.denyGrant {
			return "(root) PASSWD: /usr/bin/systemctl", nil
		}
		if len(args) > 0 && args[len(args)-1] == "/usr/bin/systemctl" && !r.denyGrant {
			return "/usr/bin/systemctl", nil
		}
		if r.allowProbe {
			return "/usr/sbin/sh", nil
		}
		return "Sorry, user deploy is not allowed to execute this command", errors.New("exit status 1")
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func sudoPolicyFixture(t *testing.T) (*Manager, *sudoPolicyRunner) {
	t.Helper()
	m, base := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true, RestrictUsers: []string{"deploy"}, Grants: []SudoGrant{{User: "deploy", Commands: []string{"/usr/bin/systemctl"}}}}, Policies: PolicyConfig{Mode: "enforce"}})
	r := &sudoPolicyRunner{fakeRunner: base, uid: "1000"}
	m.Runner = r
	put(t, m, "/etc/sudoers", []byte("root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL:ALL) NOPASSWD: ALL\n@includedir /etc/sudoers.d\n"))
	put(t, m, "/etc/sudoers.d/90-cloud-init-users", []byte("deploy ALL=(ALL) NOPASSWD:ALL\n"))
	return m, r
}

func TestSudoRestrictionOverridesBroadRulesAndWithdraws(t *testing.T) {
	m, r := sudoPolicyFixture(t)
	adminBefore, _ := os.ReadFile(m.path("/etc/sudoers.d/90-cloud-init-users"))
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.path(sudoRestrictionPath))
	if err != nil || !strings.Contains(string(raw), "deploy ALL=(ALL:ALL) !ALL\ndeploy ALL=(root) PASSWD: NOSETENV: /usr/bin/systemctl\n") {
		t.Fatalf("missing terminal deny then exact grant: %s; %v", raw, err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "sudo -n -l -U deploy -u root -- /usr/bin/systemctl") || !strings.Contains(strings.Join(r.calls, "\n"), "sudo -n -l -U deploy -u root -- /usr/sbin/sh") {
		t.Fatal("effective grant and denial were not both verified")
	}
	m.Config.Sudo.RestrictUsers = nil
	makeSudoFixtureReplaceable(t, m)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := os.ReadFile(m.path(sudoRestrictionPath))
	if err != nil || strings.Contains(string(withdrawn), "deploy ALL=(ALL:ALL) !ALL") || !strings.Contains(string(withdrawn), "PASSWD: NOSETENV: /usr/bin/systemctl") {
		t.Fatal("withdrawing restriction must remove deny-all while retaining explicitly configured grants")
	}
	m.Config.Sudo.Grants = nil
	makeSudoFixtureReplaceable(t, m)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.path(sudoRestrictionPath)); !os.IsNotExist(err) {
		t.Fatal("clearing grants and restrictions did not remove owned terminal policy")
	}
	adminAfter, _ := os.ReadFile(m.path("/etc/sudoers.d/90-cloud-init-users"))
	if !bytes.Equal(adminBefore, adminAfter) {
		t.Fatal("administrator or cloud-init rules were modified")
	}
}

func makeSudoFixtureReplaceable(t *testing.T, m *Manager) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	// POSIX can replace a read-only file through its writable directory. Clear
	// Windows' read-only attribute only in the hermetic fixture to model that.
	for _, path := range []string{sudoConfigPath, sudoRestrictionPath} {
		if err := os.Chmod(m.path(path), 0600); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func TestSudoRestrictionRejectsUnverifiablePolicyOrdering(t *testing.T) {
	for _, tc := range []struct{ name, path, data string }{
		{"rule-after-include", "/etc/sudoers", "@includedir /etc/sudoers.d\n%admin ALL=(ALL) ALL\n"},
		{"later-snippet", "/etc/sudoers.d/zzzzz-later", "deploy ALL=(ALL) ALL\n"},
		{"external-source", "/etc/nsswitch.conf", "sudoers: files sss\n"},
		{"custom-plugin", "/etc/sudo.conf", "Plugin custom_policy /usr/lib/custom.so\n"},
		{"alternate-policy-file", "/etc/sudo.conf", "Plugin sudoers_policy sudoers.so sudoers_file=/etc/other-sudoers\n"},
		{"alternate-audit-policy-file", "/etc/sudo.conf", "Plugin sudoers_audit sudoers.so sudoers_file=/etc/other-sudoers\n"},
		{"continued-audit-policy-file", "/etc/sudo.conf", "Plugin sudoers_audit sudoers.so \\\n sudoers_file=/etc/other-sudoers\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := sudoPolicyFixture(t)
			put(t, m, tc.path, []byte(tc.data))
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("unverifiable terminal policy accepted")
			}
			if _, err := os.Stat(m.path(sudoRestrictionPath)); !os.IsNotExist(err) {
				t.Fatal("preflight failure modified sudo policy")
			}
		})
	}
}

func TestSudoRestrictionChecksActualDenialAndRollsBack(t *testing.T) {
	m, r := sudoPolicyFixture(t)
	r.allowProbe = true
	if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "can still run ungranted") {
		t.Fatalf("effective broad privilege was not rejected: %v", err)
	}
	if _, err := os.Stat(m.path(sudoRestrictionPath)); !os.IsNotExist(err) {
		t.Fatal("failed validation retained new sudo override")
	}
	if _, err := os.Stat(m.path("/etc/sudoers.d/90-cloud-init-users")); err != nil {
		t.Fatal("rollback removed administrator rules")
	}
}

func TestSudoRestrictionRejectsUIDZeroAndUnknownUID(t *testing.T) {
	for _, uid := range []string{"0", "", "not-a-uid"} {
		t.Run("uid="+uid, func(t *testing.T) {
			m, r := sudoPolicyFixture(t)
			r.uid = uid
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("UID 0 alias or unverifiable identity accepted")
			}
		})
	}
}

func TestSudoRestrictionConfigurationRejectsDuplicateAndPrivilegedAccounts(t *testing.T) {
	for _, users := range [][]string{{"root"}, {"ALL"}, {"deploy", "deploy"}, {"deploy\nroot"}, make([]string, 129)} {
		cfg := Config{Sudo: SudoConfig{RestrictUsers: users}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe restricted accounts accepted: %v", users)
		}
	}
}

func TestSudoDenialProbeAvoidsGrantedFilesystemAliases(t *testing.T) {
	m, _ := sudoPolicyFixture(t)
	m.Config.Sudo.Grants = []SudoGrant{{User: "deploy", Commands: []string{"/bin/sh /approved-script"}}}
	put(t, m, "/bin/sh", []byte("same executable"))
	put(t, m, "/usr/bin/directory-anchor", []byte(""))
	if err := os.Link(m.path("/bin/sh"), m.path("/usr/bin/sh")); err != nil {
		t.Skipf("hardlinks not available: %v", err)
	}
	if !m.sudoCommandIsGranted("deploy", "/usr/bin/sh") {
		t.Fatal("a granted executable alias could be incorrectly reported as an ungranted command")
	}
	if m.sudoCommandIsGranted("someone-else", "/usr/bin/sh") {
		t.Fatal("another user's grant influenced denial probe selection")
	}
}

func TestSudoPASSWDResetsEarlierExemptionAndAllowsAuthenticateDefaults(t *testing.T) {
	m, r := sudoPolicyFixture(t)
	r.defaultsOutput = "Matching Defaults entries for deploy on test-host:\n    !authenticate, exempt_group=sudo, !exempt_group\n\nRunas and Command-specific defaults for deploy:\n    Defaults!/usr/bin/systemctl !authenticate\n\nUser deploy may run the following commands on test-host:\n    (root) PASSWD: /usr/bin/systemctl\n"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("explicit PASSWD plus loaded exemption reset should supersede !authenticate: %v", err)
	}
	raw, _ := os.ReadFile(m.path(sudoRestrictionPath))
	if !strings.Contains(string(raw), "Defaults:deploy !exempt_group\n") {
		t.Fatal("terminal policy did not neutralize global/user/compiled authentication exemptions")
	}
}

func TestSudoPASSWDRejectsLaterCommandAndRunasExemptions(t *testing.T) {
	for _, entry := range []string{"Defaults!/usr/bin/systemctl exempt_group=sudo", "Defaults>root exempt_group=sudo"} {
		t.Run(entry, func(t *testing.T) {
			m, r := sudoPolicyFixture(t)
			r.defaultsOutput = "Matching Defaults entries for deploy on test-host:\n    !exempt_group\n\nRunas and Command-specific defaults for deploy:\n    " + entry + "\n\nUser deploy may run the following commands on test-host:\n    (root) PASSWD: /usr/bin/systemctl\n"
			if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "exempt_group can bypass") {
				t.Fatalf("late authentication exemption was not rejected: %v", err)
			}
			if _, err := os.Stat(m.path(sudoRestrictionPath)); !os.IsNotExist(err) {
				t.Fatal("failed authentication validation retained a new restriction policy")
			}
		})
	}
}

func TestSudoPASSWDRequiresLoadedResetAndCompleteDefaultsOutput(t *testing.T) {
	for name, output := range map[string]string{
		"missing-reset":           "Matching Defaults entries for deploy on test-host:\n    exempt_group=sudo\n\nUser deploy may run the following commands on test-host:\n    (root) PASSWD: /usr/bin/systemctl\n",
		"truncated-or-old-format": "(root) PASSWD: /usr/bin/systemctl\n",
	} {
		t.Run(name, func(t *testing.T) {
			m, r := sudoPolicyFixture(t)
			r.defaultsOutput = output
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("unverified password authentication was treated as compliant")
			}
		})
	}
}

func TestSudoNOPASSWDDoesNotPretendToRequireAuthentication(t *testing.T) {
	m, r := sudoPolicyFixture(t)
	m.Config.Sudo.Grants[0].NoPasswd = true
	r.defaultsOutput = "Matching Defaults entries for deploy on test-host:\n    !exempt_group\n\nRunas and Command-specific defaults for deploy:\n    Defaults>root exempt_group=sudo\n\nUser deploy may run the following commands on test-host:\n    (root) NOPASSWD: /usr/bin/systemctl\n"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("explicit NOPASSWD grant does not require an authentication assertion: %v", err)
	}
	raw, _ := os.ReadFile(m.path(sudoRestrictionPath))
	if !strings.Contains(string(raw), "NOPASSWD: NOSETENV: /usr/bin/systemctl") {
		t.Fatal("NOPASSWD tag not generated explicitly")
	}
}

func TestSudoAdditiveGrantAuthenticationUsesTerminalPolicyWithoutDenyAll(t *testing.T) {
	m, _ := sudoPolicyFixture(t)
	m.Config.Sudo.RestrictUsers = nil
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(m.path(sudoRestrictionPath))
	if strings.Contains(string(raw), "deploy ALL=(ALL:ALL) !ALL") || !strings.Contains(string(raw), "Defaults:deploy !exempt_group") || !strings.Contains(string(raw), "PASSWD: NOSETENV: /usr/bin/systemctl") {
		t.Fatal("additive grant did not enforce its authentication tag independently of broad-permission restriction")
	}
	checks := m.checkSudoRestrictions(context.Background())
	if len(checks) != 1 || checks[0].Setting != "sudo.grants" || !checks[0].Compliant {
		t.Fatalf("additive authentication was not reported accurately: %+v", checks)
	}
}

func TestSudoRejectsConflictingAuthenticationTagsForSameGrant(t *testing.T) {
	m, _ := sudoPolicyFixture(t)
	m.Config.Sudo.Grants = append(m.Config.Sudo.Grants, SudoGrant{User: "deploy", RunAs: "root", Commands: []string{"/usr/bin/systemctl"}, NoPasswd: true})
	if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "conflicting sudo PASSWD/NOPASSWD") {
		t.Fatalf("contradictory authentication tags were accepted as simultaneously compliant: %v", err)
	}
	if _, err := os.Stat(m.path(sudoRestrictionPath)); !os.IsNotExist(err) {
		t.Fatal("conflicting grant modified terminal policy before rejection")
	}
}
