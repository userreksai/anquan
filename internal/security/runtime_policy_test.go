package security

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fourKernelPolicies() map[string]string {
	return map[string]string{"kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "2", "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.tcp_syncookies": "1"}
}

func TestFourKernelPoliciesApplyRepairAndWithdrawIndependently(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", Sysctl: fourKernelPolicies()}})
	for key := range m.Config.Policies.Sysctl {
		runner.values[key] = "0"
	}
	status, err := m.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.values, fourKernelPolicies()) {
		t.Fatalf("not effective: %#v", runner.values)
	}
	for _, component := range status {
		if component.Name == "policies" && (component.State != "compliant" || component.PolicyMode != "enforce" || component.CheckedAt == nil || len(component.Checks) != 4) {
			t.Fatalf("misreported policy status: %#v", component)
		}
	}
	runner.values["kernel.kptr_restrict"] = "0"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.values["kernel.kptr_restrict"] != "2" {
		t.Fatal("same-file apply did not repair runtime drift")
	}
	delete(m.Config.Policies.Sysctl, "kernel.dmesg_restrict")
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.values["kernel.dmesg_restrict"] != "0" || runner.values["kernel.kptr_restrict"] != "2" {
		t.Fatalf("individual withdrawal affected another setting: %#v", runner.values)
	}
	m.Config.Policies.Sysctl = map[string]string{}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for key, value := range runner.values {
		if value != "0" {
			t.Errorf("%s original value lost: %s", key, value)
		}
	}
	if _, err := os.Stat(m.path(sysctlConfigPath)); !os.IsNotExist(err) {
		t.Fatal("empty selection retained sysctl file")
	}
}

func TestKernelFailureRestoresActualRuntimeSnapshot(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", Sysctl: fourKernelPolicies()}})
	for key := range m.Config.Policies.Sysctl {
		runner.values[key] = "0"
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.values["kernel.kptr_restrict"] = "1" // a runtime change after the last successful configuration
	before := map[string]string{}
	for key, value := range runner.values {
		before[key] = value
	}
	oldFile, _ := os.ReadFile(m.path(sysctlConfigPath))
	m.Config.Policies.Sysctl["kernel.dmesg_restrict"] = "0"
	m.Config.Policies.Sysctl["net.ipv4.tcp_syncookies"] = "2"
	runner.fail = func(name string, args []string) error {
		if name == "sysctl" && strings.Join(args, " ") == "-w net.ipv4.tcp_syncookies=2" {
			return errors.New("kernel refused write")
		}
		return nil
	}
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("failed kernel write was committed")
	}
	if !reflect.DeepEqual(before, runner.values) {
		t.Fatalf("rollback reapplied a prior target instead of the pre-transaction runtime: want %#v got %#v", before, runner.values)
	}
	actualFile, _ := os.ReadFile(m.path(sysctlConfigPath))
	if string(actualFile) != string(oldFile) {
		t.Fatal("failed kernel policy file was not restored")
	}
	if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
		t.Fatal("successful rollback retained a pending transaction")
	}
}

func TestAuditKernelPoliciesNeverWriteHostSettings(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "audit", Sysctl: fourKernelPolicies()}})
	for key := range m.Config.Policies.Sysctl {
		runner.values[key] = "0"
	}
	statuses, err := m.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range statuses {
		if component.Name == "policies" && component.State != "audit_drift" {
			t.Fatalf("audit mismatch reported as service failure: %#v", component)
		}
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "sysctl -w") {
			t.Fatal("audit mode wrote a kernel setting")
		}
	}
	if _, err := os.Stat(m.path(sysctlConfigPath)); !os.IsNotExist(err) {
		t.Fatal("audit mode wrote sysctl persistence")
	}
}

func TestCtrlAltDelDisablesBurstAndRestoresOriginalState(t *testing.T) {
	for _, original := range []string{"static", "masked", "masked-runtime"} {
		t.Run(original, func(t *testing.T) {
			m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", DisableCtrlAltDel: true}})
			runner.cadState = original
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if runner.cadState != "masked" || runner.burstAction != "none" {
				t.Fatalf("incomplete CtrlAltDel protection: %s %s", runner.cadState, runner.burstAction)
			}
			runner.cadState, runner.burstAction = "static", "reboot-force"
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if runner.cadState != "masked" || runner.burstAction != "none" {
				t.Fatal("same-config runtime drift not repaired")
			}
			m.Config.Policies.DisableCtrlAltDel = false
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if runner.cadState != original || runner.burstAction != "reboot-force" {
				t.Fatalf("original systemd state not restored: got %s %s", runner.cadState, runner.burstAction)
			}
		})
	}
}

func TestSessionTimeoutChecksFreshBashAndReadonlyValue(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("Bash is required for a real isolated profile check")
	}
	m, _ := testManager(t, Config{Enabled: true, Policies: PolicyConfig{SessionTimeoutSeconds: 900}})
	m.Runner = commandRunner{}
	put(t, m, sessionConfigPath, []byte(sessionPolicyScript(900)))
	profile := ". '" + filepath.ToSlash(m.path(sessionConfigPath)) + "'\nTMOUT=1\n"
	put(t, m, "/etc/profile", []byte(profile))
	check := m.checkSessionTimeout(context.Background())
	if !check.Compliant {
		t.Fatalf("fresh Bash did not enforce readonly timeout: %#v", check)
	}
	put(t, m, "/etc/profile", []byte("# TMOUT=900\n"))
	if check = m.checkSessionTimeout(context.Background()); check.Compliant {
		t.Fatal("commented or unsourced assignment was accepted")
	}
	put(t, m, "/etc/profile", []byte("TMOUT=900\nexport TMOUT\n"))
	if check = m.checkSessionTimeout(context.Background()); check.Compliant {
		t.Fatal("mutable timeout was accepted")
	}
}

func TestPolicyStatusDistinguishesAuditDriftAndInspectionFailure(t *testing.T) {
	checks := []PolicyCheck{policyValueCheck("sysctl.kernel.dmesg_restrict", "1", "0", nil)}
	for _, tc := range []struct{ mode, want string }{{"audit", "audit_drift"}, {"enforce", "drift"}} {
		if state, _ := policyStatus(tc.mode, checks); state != tc.want {
			t.Errorf("%s: %s", tc.mode, state)
		}
	}
	checks[0].Error = "permission denied"
	if state, _ := policyStatus("audit", checks); state != "error" {
		t.Fatal("failed inspection hidden as a known mismatch")
	}
	if state, _ := policyStatus("enforce", nil); state != "no_policies" {
		t.Fatal("empty policy falsely claimed applied")
	}
}

func TestPeriodicReconcileOnlyMutatesEnforceMode(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "audit", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}}})
	runner.values["kernel.kptr_restrict"] = "0"
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("audit monitoring entered the mutating apply path")
	}
	m.Config.Policies.Mode = "enforce"
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.values["kernel.kptr_restrict"] = "1"
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.values["kernel.kptr_restrict"] != "2" {
		t.Fatal("enforce monitoring failed to repair drift")
	}
	var recorded error
	called := false
	m.ReconcileResult = func(statuses []ComponentStatus, err error) error { called, recorded = true, err; return nil }
	if err := m.reconcileEnforcedPolicies(context.Background()); err != nil || !called || recorded != nil {
		t.Fatal("successful reconciliation did not clear the embedding runtime's earlier error")
	}
	runner.fail = func(name string, args []string) error {
		if name == "sysctl" {
			return errors.New("sysctl unavailable")
		}
		return nil
	}
	if err := m.reconcileEnforcedPolicies(context.Background()); err == nil || recorded == nil {
		t.Fatal("failed reconciliation was not reported to the embedding runtime")
	}
}

func TestCtrlAltDelCustomUnitsArePreserved(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", DisableCtrlAltDel: true}})
	path := "/etc/systemd/system/ctrl-alt-del.target"
	before := "[Unit]\nDescription=Administrator custom unit\n"
	put(t, m, path, []byte(before))
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("custom ctrl-alt-del unit was not rejected")
	}
	after, _ := os.ReadFile(m.path(path))
	if string(after) != before {
		t.Fatal("custom target was modified")
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "systemctl mask") || strings.HasPrefix(call, "systemctl unmask") {
			t.Fatalf("custom target reached mask mutation: %s", call)
		}
	}
}

func TestCtrlAltDelBurstRollbackRunsAfterEarlierServiceFailure(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", DisableCtrlAltDel: true}})
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	// This is the state after restoring an old drop-in while an earlier service
	// rollback failed before activate could reach daemon-reexec.
	if err := os.Remove(m.path(ctrlAltDelConfigPath)); err != nil {
		t.Fatal(err)
	}
	state := "static"
	if err := m.restoreRuntime(context.Background(), nil, &state); err != nil {
		t.Fatal(err)
	}
	if runner.burstAction != "reboot-force" || runner.cadState != "static" {
		t.Fatal("restoring runtime did not restore the manager's old configuration")
	}
}

func TestGRUBPasswordHashMatchesParserRequirements(t *testing.T) {
	for _, invalid := range []string{"grub.pbkdf2.sha512.0.AB.CD", "grub.pbkdf2.sha512.010000.AB.CD", "grub.pbkdf2.sha512.+10000.AB.CD", "grub.pbkdf2.sha512.4294967296.AB.CD", "grub.pbkdf2.sha512.10000.A.CD", "grub.pbkdf2.sha512.10000.AB.C", "grub.pbkdf2.sha512.10000.AB.GG"} {
		if validGRUBPasswordHash(invalid) {
			t.Errorf("invalid credential accepted: %s", invalid)
		}
	}
	if !validGRUBPasswordHash("grub.pbkdf2.sha512.10000.ABCD.EFAB") {
		t.Fatal("tool-compatible credential rejected")
	}
}

func TestPolicyPollCadenceRetainsDurableRetryAndConfigChanges(t *testing.T) {
	m, runner := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "audit", Sysctl: map[string]string{"kernel.dmesg_restrict": "1"}}})
	runner.values["kernel.dmesg_restrict"] = "0"
	if err := m.Poll(context.Background(), func(Event) error { return errors.New("queue full") }); err == nil {
		t.Fatal("enqueue failure ignored")
	}
	events := 0
	accept := func(Event) error { events++; return nil }
	if err := m.Poll(context.Background(), accept); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatal("policy event was consumed before durable enqueue")
	}
	calls := len(runner.calls)
	if err := m.Poll(context.Background(), accept); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != calls {
		t.Fatal("fast log poll repeatedly spawned host policy probes")
	}
	m.Config.Policies.Sysctl["kernel.dmesg_restrict"] = "0"
	if err := m.Poll(context.Background(), accept); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatal("changed policy was hidden by the probe interval")
	}
}
