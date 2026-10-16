package security

import (
	"context"
	"strings"
	"testing"
)

type sshSettingsRunner struct {
	Runner
	settings string
}

func (r sshSettingsRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "sshd" && len(args) == 1 && args[0] == "-T" {
		return r.settings, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestFirewallRestrictsEveryConfiguredSSHPort(t *testing.T) {
	m, _ := testManager(t, Config{})
	m.Runner = sshSettingsRunner{Runner: m.Runner, settings: "port 22\nport 2222\nport 2200\n"}
	rules, err := m.firewallRules(context.Background(), []string{"192.0.2.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	// Both address families must allow every port for approved sources, and
	// the final rule must reject every port for all remaining sources.
	for _, want := range []string{
		"ip saddr { 192.0.2.0/24 } tcp dport { 22, 2222, 2200 } accept",
		"ip6 saddr { 2001:db8::/32 } tcp dport { 22, 2222, 2200 } accept",
		"tcp dport { 22, 2222, 2200 } drop",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("effective SSH port missing from firewall rule %q:\n%s", want, rules)
		}
	}
}
