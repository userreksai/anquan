package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// SSH commands always use this simulated Linux host, including its /proc argv.
// These tests must never read or change the machine running go test.
type sshHostRunner struct {
	*fakeRunner
	m          *Manager
	settings   string
	listeners  string
	context    func(string) string
	table      []map[string]any
	unitState  string
	socket     bool
	failReload bool
}

func sshHost(t *testing.T, m *Manager, base *fakeRunner) *sshHostRunner {
	t.Helper()
	put(t, m, "/proc/4242/cmdline", []byte("/usr/sbin/sshd\x00-D\x00"))
	put(t, m, "/etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\n"))
	r := &sshHostRunner{fakeRunner: base, m: m, unitState: "disabled", settings: "port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin no\nallowusers deploy\n", listeners: `LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=4242,fd=3))`}
	m.Runner = r
	return r
}

func (r *sshHostRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := r.fakeRunner.Run(ctx, name, args...); err != nil {
		return "", err
	}
	if name == "systemctl" && len(args) > 0 {
		unit := args[len(args)-1]
		switch args[0] {
		case "is-active":
			if strings.HasSuffix(unit, ".socket") {
				if r.socket {
					return "active", nil
				}
				return "inactive", errors.New("inactive")
			}
			return "active", nil
		case "show":
			if strings.Contains(strings.Join(args, " "), "MainPID") {
				return "4242", nil
			}
		case "is-enabled":
			if unit == "anquan-ssh-allow.service" {
				return r.unitState, nil
			}
		case "enable":
			if unit == "anquan-ssh-allow.service" {
				r.unitState = "enabled"
				if len(args) > 2 && args[1] == "--runtime" {
					r.unitState = "enabled-runtime"
				}
			}
		case "disable":
			if unit == "anquan-ssh-allow.service" {
				r.unitState = "disabled"
			}
		case "reload":
			if r.failReload {
				r.failReload = false
				return "", errors.New("simulated SSH reload failure")
			}
		}
	}
	if name == "sshd" && len(args) > 0 && args[0] == "-T" {
		if len(args) > 2 && r.context != nil {
			return r.context(args[2]), nil
		}
		return r.settings, nil
	}
	if name == "ssh" && len(args) > 1 && args[0] == "-Q" {
		// A deliberately old version with no post-quantum KEX remains usable.
		return "aes256-gcm@openssh.com\nhmac-sha2-256-etm@openssh.com\ncurve25519-sha256\nssh-ed25519\nrsa-sha2-256\n", nil
	}
	if name == "ss" {
		return r.listeners, nil
	}
	if name == "nft" {
		key := strings.Join(args, " ")
		switch key {
		case "-j list tables":
			if r.table == nil {
				return `{"nftables":[]}`, nil
			}
			return `{"nftables":[{"table":{"family":"inet","name":"anquan_ssh"}}]}`, nil
		case "-j list table inet anquan_ssh":
			b, err := json.Marshal(map[string]any{"nftables": r.table})
			return string(b), err
		case "delete table inet anquan_ssh":
			r.table = nil
			return "", nil
		}
		if len(args) == 2 && args[0] == "-f" {
			data, err := os.ReadFile(args[1])
			if err != nil {
				return "", err
			}
			rules, err := expectedSSHFirewallFromFile(string(data))
			if err != nil {
				return "", err
			}
			r.table = sshNFTFixture(rules)
			if !strings.Contains(string(data), sshFirewallMarker) {
				delete(r.table[0]["table"].(map[string]any), "comment")
			}
		}
	}
	return "", nil
}

func sshNFTFixture(rules []string) []map[string]any {
	result := []map[string]any{
		{"table": map[string]any{"family": "inet", "name": "anquan_ssh", "comment": sshFirewallMarker}},
		{"chain": map[string]any{"family": "inet", "table": "anquan_ssh", "name": "restrict_ssh", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
	}
	for _, text := range rules {
		var expr []map[string]any
		for _, token := range strings.Split(text, ";") {
			key, values, found := strings.Cut(token, "=")
			if !found {
				expr = append(expr, map[string]any{key: nil})
				continue
			}
			var left map[string]any
			switch key {
			case "interface":
				left = map[string]any{"meta": map[string]any{"key": "iifname"}}
			case "state":
				left = map[string]any{"ct": map[string]any{"key": "state"}}
			case "ports":
				left = map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}
			case "ip", "ip6":
				left = map[string]any{"payload": map[string]any{"protocol": key, "field": "saddr"}}
			}
			var set []any
			for _, value := range strings.Split(values, ",") {
				if key == "ports" {
					var n int
					fmt.Sscan(value, &n)
					set = append(set, float64(n))
				} else if key == "ip" || key == "ip6" {
					addr, prefix, _ := strings.Cut(value, "/")
					var n int
					fmt.Sscan(prefix, &n)
					set = append(set, map[string]any{"prefix": map[string]any{"addr": addr, "len": float64(n)}})
				} else {
					set = append(set, value)
				}
			}
			expr = append(expr, map[string]any{"match": map[string]any{"op": "==", "left": left, "right": map[string]any{"set": set}}})
		}
		result = append(result, map[string]any{"rule": map[string]any{"family": "inet", "table": "anquan_ssh", "chain": "restrict_ssh", "expr": expr}})
	}
	return result
}

func TestSSHForwardingAndCryptoAreSelectedFromHostSupport(t *testing.T) {
	m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, DisableForwarding: true, StrongCrypto: true}}})
	sshHost(t, m, base)
	files, err := m.desiredSSHFiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content := string(files[sshConfigPath].Data)
	for _, want := range []string{"disableforwarding yes", "allowtcpforwarding no", "permitopen none", "permitlisten none", "ciphers aes256-gcm@openssh.com", "kexalgorithms curve25519-sha256", "hostkeyalgorithms ssh-ed25519,rsa-sha2-256"} {
		if !strings.Contains(content, want+"\n") {
			t.Fatalf("missing selected policy %q: %s", want, content)
		}
	}
	if strings.Contains(content, "sntrup") {
		t.Fatal("unsupported algorithm added")
	}
}

func TestSSHRejectsNonstandardListenersAndUnsafeMatch(t *testing.T) {
	for _, tc := range []struct {
		name, argv, config string
		socket             bool
	}{
		{"custom config", "/usr/sbin/sshd\x00-f\x00/etc/custom-ssh\x00", "", false},
		{"custom port", "/usr/sbin/sshd\x00-p\x002202\x00", "", false},
		{"socket activation", "", "", true},
		{"group Match", "", "Include /etc/ssh/sshd_config.d/*.conf\nMatch Group admin\n PasswordAuthentication yes\n", false},
		{"conditional Include", "", "Match User deploy\n Include /etc/ssh/sshd_config.d/*.conf\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true}}})
			r := sshHost(t, m, base)
			r.socket = tc.socket
			if tc.argv != "" {
				put(t, m, "/proc/4242/cmdline", []byte(tc.argv))
			}
			if tc.config != "" {
				put(t, m, "/etc/ssh/sshd_config", []byte(tc.config))
			}
			if _, err := m.desiredSSHFiles(context.Background()); err == nil {
				t.Fatal("unverifiable deployment accepted")
			}
			if _, err := os.Stat(m.path(sshConfigPath)); !os.IsNotExist(err) {
				t.Fatal("preflight changed SSH config")
			}
		})
	}
}

func TestSSHMatchOverrideAndAppendedUsersAreNotCertified(t *testing.T) {
	m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "audit", SSH: SSHConfig{Enabled: true, PasswordAuthentication: "no", AllowUsers: []string{"deploy"}}}})
	r := sshHost(t, m, base)
	put(t, m, "/etc/ssh/sshd_config.d/admin.conf", []byte("Match Address 10.0.0.0/8\n PasswordAuthentication yes\n"))
	r.context = func(c string) string {
		if strings.Contains(c, "addr=10.0.0.0,") {
			return strings.Replace(r.settings, "passwordauthentication no", "passwordauthentication yes", 1)
		}
		return r.settings
	}
	if err := m.validateSSHPolicy(context.Background()); err == nil || !strings.Contains(err.Error(), "10.0.0.0") {
		t.Fatalf("Match override ignored: %v", err)
	}
	r.context = nil
	r.settings = strings.Replace(r.settings, "allowusers deploy", "allowusers deploy admin", 1)
	if err := m.validateSSHPolicy(context.Background()); err == nil {
		t.Fatal("appended broad AllowUsers accepted")
	}
}

func TestSSHSourceRestrictionLifecycleAndRuntimeDrift(t *testing.T) {
	m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, PasswordAuthentication: "no", PermitRootLogin: "no", AllowUsers: []string{"deploy"}, AllowSources: []string{"192.0.2.0/24", "2001:db8::/32"}}}})
	r := sshHost(t, m, base)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.validateSSHFirewall(context.Background(), m.Config.Policies.SSH.AllowSources); err != nil {
		t.Fatal(err)
	}
	if r.unitState != "enabled" {
		t.Fatal("restriction is not persistent")
	}
	// Keeping the chain but deleting its final deny must be detected and repaired.
	r.table = r.table[:len(r.table)-1]
	if err := m.validateSSHFirewall(context.Background(), m.Config.Policies.SSH.AllowSources); err == nil {
		t.Fatal("chain-only firewall certified")
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.validateSSHFirewall(context.Background(), m.Config.Policies.SSH.AllowSources); err != nil {
		t.Fatalf("runtime drift not repaired: %v", err)
	}
	m.Config.Policies.SSH.AllowSources = nil
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.table != nil || r.unitState != "disabled" {
		t.Fatal("withdrawal did not restore firewall/unit")
	}
}

func TestSSHFirewallRefusesForeignTableAndDormantBypass(t *testing.T) {
	m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, AllowSources: []string{"192.0.2.0/24"}}}})
	r := sshHost(t, m, base)
	r.table = sshNFTFixture([]string{"interface=lo;accept", "state=established,related;accept", "ip=192.0.2.0/24;ports=2222;accept", "ports=2222;drop"})
	r.table[0]["table"].(map[string]any)["comment"] = "administrator table"
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("foreign same-name table overwritten")
	}
	for _, call := range base.calls {
		if strings.HasPrefix(call, "nft -f ") || call == "nft delete table inet anquan_ssh" {
			t.Fatalf("foreign table mutated: %s", call)
		}
	}
	r.table[0]["table"].(map[string]any)["comment"] = sshFirewallMarker
	r.table[0]["table"].(map[string]any)["flags"] = []string{"dormant"}
	if err := m.validateSSHFirewall(context.Background(), m.Config.Policies.SSH.AllowSources); err == nil {
		t.Fatal("dormant table bypass accepted")
	}
}

func TestSSHFirewallRestoresPreexistingUnitEnableState(t *testing.T) {
	for _, initial := range []string{"enabled", "enabled-runtime", "disabled"} {
		t.Run(initial, func(t *testing.T) {
			m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, AllowSources: []string{"192.0.2.0/24"}}}})
			r := sshHost(t, m, base)
			r.unitState = initial
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			m.Config.Enabled = false
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.unitState != initial {
				t.Fatalf("unit enable state %s replaced by %s", initial, r.unitState)
			}
		})
	}
}

func TestSSHReloadFailureRestoresPreviousConfigAndRules(t *testing.T) {
	m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, PasswordAuthentication: "no", AllowSources: []string{"192.0.2.0/24"}}}})
	r := sshHost(t, m, base)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.path(sshConfigPath))
	m.Config.Policies.SSH.PermitRootLogin = "no"
	m.Config.Policies.SSH.AllowSources = []string{"198.51.100.0/24"}
	r.failReload = true
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("reload failure was acknowledged")
	}
	after, _ := os.ReadFile(m.path(sshConfigPath))
	if string(after) != string(before) {
		t.Fatal("SSH rollback did not restore the previous file")
	}
	if err := m.validateSSHFirewall(context.Background(), []string{"192.0.2.0/24"}); err != nil {
		t.Fatalf("firewall rollback failed: %v", err)
	}
	if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
		t.Fatalf("successful rollback left a journal: %v", err)
	}
}

func TestSSHUpgradesOnlyProvenLegacyFirewallAndCanRollItBack(t *testing.T) {
	for _, failReload := range []bool{false, true} {
		t.Run(fmt.Sprint("reloadFailure=", failReload), func(t *testing.T) {
			m, base := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", SSH: SSHConfig{Enabled: true, PasswordAuthentication: "no", AllowSources: []string{"192.0.2.0/24"}}}})
			r := sshHost(t, m, base)
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(m.path(firewallConfigPath))
			legacy := strings.Replace(string(data), " comment \""+sshFirewallMarker+"\"\n", "", 1)
			put(t, m, firewallConfigPath, []byte(legacy))
			delete(r.table[0]["table"].(map[string]any), "comment")
			state, err := m.loadManifest()
			if err != nil {
				t.Fatal(err)
			}
			state.Files[firewallConfigPath] = hashString(legacy)
			if err := writePrivateJSON(m.manifestPath(), "security-managed", state); err != nil {
				t.Fatal(err)
			}
			if failReload {
				m.Config.Policies.SSH.PermitRootLogin = "no"
				r.failReload = true
			}
			_, err = m.Apply(context.Background())
			if failReload {
				if err == nil {
					t.Fatal("reload failure ignored")
				}
				data, _ := os.ReadFile(m.path(firewallConfigPath))
				if string(data) != legacy {
					t.Fatal("legacy firewall file not restored")
				}
				if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
					t.Fatalf("legacy rollback incomplete: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := m.validateSSHFirewall(context.Background(), m.Config.Policies.SSH.AllowSources); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSSHSourceNormalizationDoesNotExpandAllowedNetworks(t *testing.T) {
	v4, v6, err := normalizedSSHSources([]string{"192.0.2.1", "192.0.2.0/24", "192.0.2.128/25", "192.0.2.0/24", "2001:db8::1", "2001:db8::/32", "198.51.100.1"})
	if err != nil || strings.Join(v4, ",") != "192.0.2.0/24,198.51.100.1/32" || strings.Join(v6, ",") != "2001:db8::/32" {
		t.Fatalf("source normalization changed the allowed union: %v %v %v", v4, v6, err)
	}
	if _, _, err := normalizedSSHSources([]string{"fe80::1%eth0"}); err == nil {
		t.Fatal("interface-scoped source silently broadened")
	}
}
