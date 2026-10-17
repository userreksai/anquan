package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const (
	runtimeAuditRuleA         = "-a always,exit -F arch=b64 -S execve -F auid=1001 -k anquan_exec"
	runtimeAuditRuleB         = "-a always,exit -F arch=b64 -S execve -F auid=1002 -k anquan_exec"
	runtimeAuditRuleC         = "-a always,exit -F arch=b64 -S execve -F auid=1003 -k anquan_exec"
	runtimeAdminRule          = "-a always,exit -F arch=b64 -S execve -F auid=9001 -k anquan_exec"
	runtimeAdminSubstringRule = "-a always,exit -F arch=b64 -S execve -F auid=9002 -k anquan_exec_admin"
	runtimeAuditWatch         = "-w /etc/hosts -p wa -k anquan_file"
)

// This runner models kernel state rather than assuming every auditctl command
// succeeds. In particular, an identical rule fails even when auditd loaded it
// while starting, before the Agent has run auditctl itself.
type statefulAuditRunner struct {
	*fakeRunner
	manager        *Manager
	rules          map[string]bool
	operations     []string
	preloadOnStart bool
	immutable      bool
	failRule       func(string) (string, error)
	afterOperation func(string)
}

func runtimeRuleLines(raw string) []string {
	var rules []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			rules = append(rules, line)
		}
	}
	return rules
}

func (r *statefulAuditRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if name == "systemctl" && strings.Join(args, " ") == "enable --now auditd" {
		out, err := r.fakeRunner.Run(ctx, name, args...)
		if err == nil && r.preloadOnStart {
			r.preloadOnStart = false
			raw, readErr := os.ReadFile(r.manager.path(auditRulesPath))
			if readErr != nil {
				return "", readErr
			}
			for _, rule := range runtimeRuleLines(string(raw)) {
				r.rules[rule] = true
			}
		}
		return out, err
	}
	if name != "auditctl" || len(args) == 0 || (args[0] != "-R" && args[0] != "-s" && args[0] != "-D") {
		return r.fakeRunner.Run(ctx, name, args...)
	}
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if args[0] == "-D" {
		return "", errors.New("unsafe bulk audit deletion requested")
	}
	if args[0] == "-s" {
		if r.immutable {
			return "enabled 2\nlost 0\n", nil
		}
		return "enabled 1\nlost 0\n", nil
	}
	if len(args) != 2 {
		return "", fmt.Errorf("unexpected auditctl arguments: %q", args)
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return "", err
	}
	info, err := os.Stat(args[1])
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		return "", fmt.Errorf("temporary audit rules mode is %04o, want 0600", info.Mode().Perm())
	}
	rules := runtimeRuleLines(string(raw))
	if len(rules) != 1 {
		return "", fmt.Errorf("audit load must contain exactly one rule, got %d", len(rules))
	}
	rule := rules[0]
	r.operations = append(r.operations, rule)
	if r.failRule != nil {
		if out, err := r.failRule(rule); err != nil {
			return out, err
		}
	}
	if r.immutable {
		return "Error sending add rule data request (Operation not permitted)", errors.New("exit status 1")
	}
	adding := strings.HasPrefix(rule, "-a ") || strings.HasPrefix(rule, "-w ")
	if adding {
		if r.rules[rule] {
			return "Error sending add rule data request (Rule exists)\nThere was an error in line 1 of " + args[1], errors.New("exit status 1")
		}
		r.rules[rule] = true
		if r.afterOperation != nil {
			r.afterOperation(rule)
		}
		return "", nil
	}
	var original string
	switch {
	case strings.HasPrefix(rule, "-d "):
		original = "-a " + strings.TrimPrefix(rule, "-d ")
	case strings.HasPrefix(rule, "-W "):
		original = "-w " + strings.TrimPrefix(rule, "-W ")
	default:
		return "", fmt.Errorf("unexpected audit rule operation %q", rule)
	}
	if !r.rules[original] {
		return "Error sending delete rule data request (No such file or directory)\nThere was an error in line 1 of " + args[1], errors.New("exit status 1")
	}
	delete(r.rules, original)
	if r.afterOperation != nil {
		r.afterOperation(rule)
	}
	return "", nil
}

func runtimeAuditManager(t *testing.T, rules ...string) (*Manager, *statefulAuditRunner) {
	t.Helper()
	m, base := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true, Rules: rules}})
	r := &statefulAuditRunner{fakeRunner: base, manager: m, rules: map[string]bool{}}
	m.Runner = r
	return m, r
}

func requireRuntimeRules(t *testing.T, r *statefulAuditRunner, rules ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, rule := range rules {
		want[rule] = true
	}
	if !reflect.DeepEqual(r.rules, want) {
		t.Fatalf("kernel audit rules = %#v, want %#v", r.rules, want)
	}
}

func requireAuditOwnership(t *testing.T, m *Manager, rules ...string) {
	t.Helper()
	state, err := m.loadManifest()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, rule := range rules {
		want[rule] = true
	}
	if len(state.AuditRules) != len(want) {
		t.Fatalf("audit ownership = %#v, want %#v", state.AuditRules, want)
	}
	for rule := range want {
		if !state.AuditRules[rule] {
			t.Fatalf("audit rule ownership missing for %q: %#v", rule, state.AuditRules)
		}
	}
}

func TestAuditRuntimeStartupPreloadedRulesDoNotFailOrAcquireOwnership(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA, runtimeAuditRuleB)
	r.preloadOnStart = true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("auditd-preloaded rules should be reused: %v", err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAuditRuleB)
	requireAuditOwnership(t, m)
	if len(r.operations) != 2 {
		t.Fatalf("duplicate first rule stopped remaining rules: %q", r.operations)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAuditRuleB)
}

func TestAuditRuntimeLostManifestReusesFileAndContinuesAfterDuplicate(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA, runtimeAuditRuleB)
	m.Config.Normalize()
	desired, _, err := m.desiredFiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	put(t, m, auditRulesPath, desired[auditRulesPath].Data)
	r.rules[runtimeAuditRuleA] = true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAuditRuleB)
	requireAuditOwnership(t, m, runtimeAuditRuleB)
	state, err := m.loadManifest()
	if err != nil || state.Files[auditRulesPath] != "" || state.ReferencedFiles[auditRulesPath] == "" {
		t.Fatalf("existing rule file should remain a reference: %#v, %v", state, err)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA)
	after, err := os.ReadFile(m.path(auditRulesPath))
	if err != nil || !bytes.Equal(after, desired[auditRulesPath].Data) {
		t.Fatalf("referenced rule file changed on disable: %q, %v", after, err)
	}
}

func TestAuditRuntimeAddFailureRollsBackPartialChanges(t *testing.T) {
	for _, failure := range []struct{ name, output, message string }{
		{"kernel error", "Error sending add rule data request (Invalid argument)", "exit status 1"},
		{"unrelated text", "invalid argument while parsing comment (Rule exists)", "exit status 1"},
		{"mixed diagnostic", "Error sending add rule data request (Rule exists)\nPermission denied", "exit status 1"},
		{"wrong rule line", "Error sending add rule data request (Rule exists)\nThere was an error in line 2 of /tmp/another.rules", "exit status 1"},
		{"error text only", "", "Error sending add rule data request (Rule exists)"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			m, r := runtimeAuditManager(t, runtimeAuditRuleA)
			r.rules[runtimeAdminRule] = true
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(m.path(auditRulesPath))
			if err != nil {
				t.Fatal(err)
			}
			m.Config.Auditd.Rules = []string{runtimeAuditRuleB, runtimeAuditRuleC}
			r.failRule = func(rule string) (string, error) {
				if rule == runtimeAuditRuleC {
					return failure.output, errors.New(failure.message)
				}
				return "", nil
			}
			_, applyErr := m.Apply(context.Background())
			if applyErr == nil {
				t.Fatal("real audit load failure was swallowed")
			}
			t.Logf("activation failure: %v", applyErr)
			requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAdminRule)
			requireAuditOwnership(t, m, runtimeAuditRuleA)
			after, err := os.ReadFile(m.path(auditRulesPath))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed activation did not restore old rules file: %q, %v", after, err)
			}
			if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
				t.Fatalf("successful rollback left a transaction journal: %v", err)
			}
		})
	}
}

func TestAuditRuntimeLaterComponentFailureRestoresOwnedAndUnownedRules(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA)
	r.rules[runtimeAdminRule] = true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Config.Auditd.Rules = []string{runtimeAuditRuleB}
	m.Config.Tetragon.Enabled = true
	failed := false
	r.fail = func(name string, args []string) error {
		if !failed && name == "systemctl" && strings.Join(args, " ") == "restart tetragon" {
			failed = true
			return errors.New("tetragon service startup failed")
		}
		return nil
	}
	if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "tetragon service startup failed") {
		t.Fatalf("expected downstream activation error, got %v", err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAdminRule)
	requireAuditOwnership(t, m, runtimeAuditRuleA)
}

func TestAuditRuntimeInitialApplyRollbackPreservesUnownedDuplicate(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA, runtimeAuditRuleB)
	r.rules[runtimeAuditRuleA] = true
	r.rules[runtimeAdminRule] = true
	m.Config.Tetragon.Enabled = true
	failed := false
	r.fail = func(name string, args []string) error {
		if !failed && name == "systemctl" && strings.Join(args, " ") == "restart tetragon" {
			failed = true
			return errors.New("tetragon service startup failed")
		}
		return nil
	}
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("expected downstream activation error")
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAdminRule)
	if _, err := os.Stat(m.path(auditRulesPath)); !os.IsNotExist(err) {
		t.Fatalf("failed initial activation left the new rule file: %v", err)
	}
}

func TestAuditRuntimeCancellationAfterSuccessfulMutationStillRollsBack(t *testing.T) {
	for _, operation := range []string{"add", "delete"} {
		t.Run(operation, func(t *testing.T) {
			m, r := runtimeAuditManager(t, runtimeAuditRuleA)
			r.rules[runtimeAdminRule] = true
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.Config.Auditd.Rules = []string{runtimeAuditRuleA, runtimeAuditRuleB}
			cancelAfter := runtimeAuditRuleB
			if operation == "delete" {
				m.Config.Auditd.Rules = []string{runtimeAuditRuleB}
				cancelAfter = "-d " + strings.TrimPrefix(runtimeAuditRuleA, "-a ")
			}
			r.afterOperation = func(rule string) {
				if rule == cancelAfter {
					cancel()
				}
			}
			if _, err := m.Apply(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation after a successful %s, got %v", operation, err)
			}
			requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAdminRule)
			requireAuditOwnership(t, m, runtimeAuditRuleA)
			if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
				t.Fatalf("completed cancellation rollback left a journal: %v", err)
			}
		})
	}
}

func TestAuditRuntimeInterruptedTransactionRecoversBeforeApplyingCurrentConfiguration(t *testing.T) {
	for _, failRecoveryOnce := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry_recovery=%t", failRecoveryOnce), func(t *testing.T) {
			m, r := runtimeAuditManager(t, runtimeAuditRuleA)
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			previous, err := m.loadManifest()
			if err != nil {
				t.Fatal(err)
			}
			oldFile, err := os.ReadFile(m.path(auditRulesPath))
			if err != nil {
				t.Fatal(err)
			}
			m.Config.Auditd.Rules = []string{runtimeAuditRuleB}
			desired, _, err := m.desiredFiles(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			newFile := desired[auditRulesPath].Data
			put(t, m, auditRulesPath, newFile)
			journal := transactionJournal{
				Before:   []snapshot{{Path: auditRulesPath, Exists: true, Data: oldFile, Mode: 0600}},
				Previous: previous,
				Next: manifest{
					Files:             map[string]string{auditRulesPath: hashString(string(newFile))},
					AuditRules:        map[string]bool{runtimeAuditRuleB: true},
					AuditRulesTracked: true,
				},
				Dirty: map[string]bool{auditRulesPath: true},
			}
			if err := writePrivateJSON(m.journalPath(), "security-transaction", journal); err != nil {
				t.Fatal(err)
			}
			// The process stopped after replacing A with B, before committing its
			// manifest. Administrator rules share its keys but remain unrelated.
			r.rules = map[string]bool{runtimeAuditRuleB: true, runtimeAdminRule: true, runtimeAdminSubstringRule: true}
			r.operations = nil
			m.Config.Auditd.Rules = []string{runtimeAuditRuleC}
			if failRecoveryOnce {
				failed := false
				r.failRule = func(rule string) (string, error) {
					if rule == runtimeAuditRuleA && !failed {
						failed = true
						return "Error sending add rule data request (Permission denied)", errors.New("exit status 1")
					}
					return "", nil
				}
				if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "recover previous security services") {
					t.Fatalf("expected interrupted recovery failure, got %v", err)
				}
				requireRuntimeRules(t, r, runtimeAdminRule, runtimeAdminSubstringRule)
				var retry transactionJournal
				if err := readPrivateJSON(m.journalPath(), "security-transaction", &retry); err != nil {
					t.Fatalf("failed recovery lost its journal: %v", err)
				}
				if !reflect.DeepEqual(retry.Previous.AuditRules, map[string]bool{runtimeAuditRuleA: true}) || retry.Previous.Files[auditRulesPath] != hashString(string(oldFile)) {
					t.Fatalf("saving recovery progress modified original rollback state: %#v", retry.Previous)
				}
				if len(retry.Next.AuditRules) != 0 || !retry.Next.AuditRulesTracked {
					t.Fatalf("recovery journal did not save the successful deletion of B: %#v", retry.Next)
				}
			}
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatalf("recovery and current configuration failed: %v", err)
			}
			requireRuntimeRules(t, r, runtimeAuditRuleC, runtimeAdminRule, runtimeAdminSubstringRule)
			requireAuditOwnership(t, m, runtimeAuditRuleC)
			wantOperations := []string{
				"-d " + strings.TrimPrefix(runtimeAuditRuleB, "-a "),
				runtimeAuditRuleA,
			}
			if failRecoveryOnce {
				wantOperations = append(wantOperations, runtimeAuditRuleA)
			}
			wantOperations = append(wantOperations, "-d "+strings.TrimPrefix(runtimeAuditRuleA, "-a "), runtimeAuditRuleC)
			if !reflect.DeepEqual(r.operations, wantOperations) {
				t.Fatalf("recovery must restore A before applying C: %q, want %q", r.operations, wantOperations)
			}
			if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
				t.Fatalf("successful recovery left a transaction journal: %v", err)
			}
		})
	}
}

func TestAuditRuntimeUpdateAndDisableDeleteOnlyExactOwnedRules(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA, runtimeAuditWatch)
	r.rules[runtimeAdminRule] = true
	r.rules[runtimeAdminSubstringRule] = true
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireAuditOwnership(t, m, runtimeAuditRuleA, runtimeAuditWatch)
	m.Config.Auditd.Rules = []string{runtimeAuditRuleB}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleB, runtimeAdminRule, runtimeAdminSubstringRule)
	requireAuditOwnership(t, m, runtimeAuditRuleB)
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule, runtimeAdminSubstringRule)
	requireAuditOwnership(t, m)
}

func TestAuditRuntimeOwnedDuplicateKeepsOwnershipAcrossUpdate(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Config.Auditd.Rules = []string{runtimeAuditRuleA, runtimeAuditRuleB}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAuditRuleB)
	requireAuditOwnership(t, m, runtimeAuditRuleA, runtimeAuditRuleB)
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireRuntimeRules(t, r)
}

func TestAuditRuntimeLegacyOwnershipUpgradeRequiresOwnedMatchingFile(t *testing.T) {
	for _, ownership := range []string{"owned", "referenced", "modified"} {
		t.Run(ownership, func(t *testing.T) {
			m, r := runtimeAuditManager(t, runtimeAuditRuleA)
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			state, err := m.loadManifest()
			if err != nil {
				t.Fatal(err)
			}
			state.AuditRules = nil
			state.AuditRulesTracked = false
			state.AuditKeys = []string{"anquan_exec"}
			if ownership == "referenced" {
				state.ReferencedFiles = map[string]string{auditRulesPath: state.Files[auditRulesPath]}
				delete(state.Files, auditRulesPath)
			}
			if ownership == "modified" {
				put(t, m, auditRulesPath, []byte(runtimeAdminRule+"\n"))
			}
			if err := writePrivateJSON(m.manifestPath(), "security-managed", state); err != nil {
				t.Fatal(err)
			}
			r.rules[runtimeAdminRule] = true
			r.rules[runtimeAdminSubstringRule] = true
			m.Config.Enabled = false
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if ownership != "owned" {
				requireRuntimeRules(t, r, runtimeAuditRuleA, runtimeAdminRule, runtimeAdminSubstringRule)
			} else {
				requireRuntimeRules(t, r, runtimeAdminRule, runtimeAdminSubstringRule)
			}
		})
	}
}

func TestAuditRuntimeDuplicateConfigurationLoadsAndDeletesOnce(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA, runtimeAuditRuleA)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.operations) != 1 || r.operations[0] != runtimeAuditRuleA {
		t.Fatalf("identical configured rules were not deduplicated: %q", r.operations)
	}
	requireAuditOwnership(t, m, runtimeAuditRuleA)
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.operations) != 2 {
		t.Fatalf("owned duplicate rule should be removed once: %q", r.operations)
	}
	requireRuntimeRules(t, r)
}

func TestAuditRuntimeAlreadyMissingOwnedRuleCanBeDisabled(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	delete(r.rules, runtimeAuditRuleA)
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("a missing exact owned rule should not block disable: %v", err)
	}
	requireRuntimeRules(t, r)
	requireAuditOwnership(t, m)
}

func TestAuditRuntimeImmutableKernelStillRejectsActivation(t *testing.T) {
	m, r := runtimeAuditManager(t, runtimeAuditRuleA)
	r.immutable = true
	r.rules[runtimeAdminRule] = true
	if _, err := m.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("immutable audit policy was accepted: %v", err)
	}
	requireRuntimeRules(t, r, runtimeAdminRule)
	if len(r.operations) != 0 {
		t.Fatalf("attempted to mutate immutable audit policy: %q", r.operations)
	}
	if _, err := os.Stat(m.path(auditRulesPath)); !os.IsNotExist(err) {
		t.Fatalf("failed activation left the new rule file: %v", err)
	}
}
