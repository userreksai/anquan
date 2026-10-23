package security

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestAuditInspectionFailureDoesNotRemainSticky(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "audit", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}}})
	r.values["kernel.kptr_restrict"] = "2"
	r.fail = func(n string, args []string) error {
		if n == "sysctl" {
			return errors.New("transient syscall failure")
		}
		return nil
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.fail = nil
	for _, s := range m.Status(context.Background()) {
		if s.Name == "policies" && s.State != "audit" {
			t.Fatalf("recovered audit checks still reported %s (%s), checks=%+v", s.State, s.Message, s.Checks)
		}
	}
}

func TestUnrecoverableManifestMustNotReportHealthyPolicies(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", Sysctl: map[string]string{"kernel.kptr_restrict": "2"}}})
	r.values["kernel.kptr_restrict"] = "0"
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.manifestPath(), []byte("corrupted encrypted ownership state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileEnforcedPolicies(context.Background()); err == nil {
		t.Fatal("expected corrupt manifest failure")
	}
	for _, s := range m.Status(context.Background()) {
		if s.Name == "policies" && s.State == "compliant" {
			t.Fatalf("reconciliation cannot load ownership, but status remains healthy: %+v", s)
		}
	}
}
