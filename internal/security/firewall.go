package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const sshFirewallMarker = "anquan-managed-ssh-v1"

func (m *Manager) sshFirewallUnitState(ctx context.Context) (string, error) {
	out, err := m.Runner.Run(ctx, "systemctl", "is-enabled", "anquan-ssh-allow.service")
	state := strings.TrimSpace(out)
	switch state {
	case "enabled", "enabled-runtime", "disabled", "not-found":
		return state, nil
	}
	if err != nil && (strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "not-found")) {
		return "not-found", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot safely preserve SSH firewall unit state %q: %w", state, err)
	}
	return "", fmt.Errorf("cannot safely preserve SSH firewall unit state %q", state)
}

func (m *Manager) firewallRules(ctx context.Context, sources []string) (string, error) {
	ports, err := m.sshListeningPorts(ctx)
	if err != nil {
		return "", err
	}
	v4, v6, err := normalizedSSHSources(sources)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	// An nft batch is atomic. Adding the empty table first allows the same
	// script to replace our table when it exists and create it on first boot.
	b.WriteString("# Managed by anquan; does not flush other firewall tables.\ntable inet anquan_ssh {}\ndelete table inet anquan_ssh\ntable inet anquan_ssh {\n comment \"" + sshFirewallMarker + "\"\n chain restrict_ssh {\n  type filter hook input priority -10; policy accept;\n  iifname \"lo\" accept\n  ct state established,related accept\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "  ip saddr { %s } tcp dport { %s } accept\n", strings.Join(v4, ", "), strings.Join(ports, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "  ip6 saddr { %s } tcp dport { %s } accept\n", strings.Join(v6, ", "), strings.Join(ports, ", "))
	}
	fmt.Fprintf(&b, "  tcp dport { %s } drop\n }\n}\n", strings.Join(ports, ", "))
	return b.String(), nil
}

func (m *Manager) sshListeningPorts(ctx context.Context) ([]string, error) {
	_, pid, err := m.sshRuntime(ctx)
	if err != nil {
		return nil, err
	}
	out, err := m.Runner.Run(ctx, "sshd", "-T")
	if err != nil {
		return nil, err
	}
	configured := strings.Fields(parseSettings(out)["port"])
	if len(configured) == 0 {
		return nil, errors.New("cannot determine effective SSH listening ports")
	}
	expected := map[string]bool{}
	for _, p := range configured {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid SSH listening port")
		}
		expected[strconv.Itoa(n)] = true
	}
	out, err = m.Runner.Run(ctx, "ss", "-H", "-ltnp")
	if err != nil {
		return nil, fmt.Errorf("verify active SSH listening ports: %w", err)
	}
	actual := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `("sshd",pid=`) && !strings.Contains(line, "pid="+pid+",") {
			return nil, errors.New("an additional SSH daemon is listening outside the managed service")
		}
		if !strings.Contains(line, "pid="+pid+",") {
			continue
		}
		v := strings.Fields(line)
		if len(v) < 5 {
			return nil, errors.New("unrecognized ss listener output")
		}
		_, port, ok := strings.Cut(v[3], "]:")
		if !ok {
			idx := strings.LastIndex(v[3], ":")
			if idx < 0 {
				return nil, errors.New("unrecognized SSH listener address")
			}
			port = v[3][idx+1:]
		}
		actual[port] = true
	}
	if strings.Join(sortedKeys(actual), ",") != strings.Join(sortedKeys(expected), ",") {
		return nil, sshPolicyMismatch("actual SSH listener ports differ from sshd_config; custom arguments or socket activation require explicit integration")
	}
	// Preserve the daemon's port ordering for stable generated files.
	return configured, nil
}

type sshFirewallState struct {
	present, owned bool
	rules          []string
}

func (m *Manager) readSSHFirewall(ctx context.Context) (sshFirewallState, error) {
	out, err := m.Runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return sshFirewallState{}, err
	}
	var list struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return sshFirewallState{}, fmt.Errorf("decode nft table inventory: %w", err)
	}
	present := false
	for _, entry := range list.NFTables {
		if raw := entry["table"]; raw != nil {
			var t struct{ Family, Name string }
			if err := json.Unmarshal(raw, &t); err != nil {
				return sshFirewallState{}, err
			}
			if t.Family == "inet" && t.Name == "anquan_ssh" {
				present = true
			}
		}
	}
	if !present {
		return sshFirewallState{}, nil
	}
	out, err = m.Runner.Run(ctx, "nft", "-j", "list", "table", "inet", "anquan_ssh")
	if err != nil {
		return sshFirewallState{}, err
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return sshFirewallState{}, err
	}
	s := sshFirewallState{present: true}
	chains, tables := 0, 0
	for _, entry := range list.NFTables {
		if raw := entry["table"]; raw != nil {
			var t struct {
				Family, Name, Comment string
				Flags                 []string
			}
			if err := json.Unmarshal(raw, &t); err != nil {
				return s, err
			}
			if t.Family != "inet" || t.Name != "anquan_ssh" {
				return s, errors.New("unexpected nft table")
			}
			s.owned = t.Comment == sshFirewallMarker
			tables++
			if len(t.Flags) > 0 {
				return s, sshPolicyMismatch("SSH nft table has unsupported flags (including dormant bypass)")
			}
			continue
		}
		if raw := entry["chain"]; raw != nil {
			var c struct {
				Family, Table, Name, Type, Hook, Policy string
				Prio                                    int
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				return s, err
			}
			if c.Family != "inet" || c.Table != "anquan_ssh" || c.Name != "restrict_ssh" || c.Type != "filter" || c.Hook != "input" || c.Prio != -10 || c.Policy != "accept" {
				return s, sshPolicyMismatch("SSH nft chain attributes drifted")
			}
			chains++
			continue
		}
		if raw := entry["rule"]; raw != nil {
			var r struct {
				Family, Table, Chain string
				Expr                 []map[string]any
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return s, err
			}
			if r.Family != "inet" || r.Table != "anquan_ssh" || r.Chain != "restrict_ssh" {
				return s, errors.New("unexpected SSH nft rule chain")
			}
			rule, err := canonicalSSHRule(r.Expr)
			if err != nil {
				return s, err
			}
			s.rules = append(s.rules, rule)
			continue
		}
		if entry["metainfo"] == nil {
			return s, errors.New("unexpected object in SSH nft table")
		}
	}
	if tables != 1 || chains != 1 {
		return s, sshPolicyMismatch("SSH nft table must contain exactly its managed input chain")
	}
	return s, nil
}

func canonicalSSHRule(expressions []map[string]any) (string, error) {
	var parts []string
	for _, expr := range expressions {
		if len(expr) != 1 {
			return "", errors.New("unrecognized SSH nft expression")
		}
		if _, ok := expr["accept"]; ok {
			parts = append(parts, "accept")
			continue
		}
		if _, ok := expr["drop"]; ok {
			parts = append(parts, "drop")
			continue
		}
		match, ok := expr["match"].(map[string]any)
		if !ok {
			return "", errors.New("unexpected SSH nft expression")
		}
		op, _ := match["op"].(string)
		if op != "==" && op != "in" {
			return "", errors.New("unexpected SSH nft match operator")
		}
		left, _ := match["left"].(map[string]any)
		key := ""
		if v, ok := left["meta"].(map[string]any); ok && v["key"] == "iifname" {
			key = "interface"
		}
		if v, ok := left["ct"].(map[string]any); ok && v["key"] == "state" {
			key = "state"
		}
		if v, ok := left["payload"].(map[string]any); ok {
			if v["field"] == "saddr" && (v["protocol"] == "ip" || v["protocol"] == "ip6") {
				key = fmt.Sprint(v["protocol"])
			}
			if v["field"] == "dport" && v["protocol"] == "tcp" {
				key = "ports"
			}
		}
		if key == "" {
			return "", errors.New("unexpected SSH nft match field")
		}
		values, err := sshNFTValues(match["right"], key)
		if err != nil {
			return "", err
		}
		sort.Strings(values)
		parts = append(parts, key+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, ";"), nil
}

func sshNFTValues(value any, key string) ([]string, error) {
	if v, ok := value.(map[string]any); ok {
		if set, ok := v["set"].([]any); ok {
			var result []string
			for _, item := range set {
				values, err := sshNFTValues(item, key)
				if err != nil {
					return nil, err
				}
				result = append(result, values...)
			}
			return result, nil
		}
		if prefix, ok := v["prefix"].(map[string]any); ok && (key == "ip" || key == "ip6") {
			a, e := netip.ParseAddr(fmt.Sprint(prefix["addr"]))
			bits, ok := prefix["len"].(float64)
			if e != nil || !ok {
				return nil, errors.New("invalid SSH nft address prefix")
			}
			p := netip.PrefixFrom(a, int(bits))
			if !p.IsValid() {
				return nil, errors.New("invalid SSH nft prefix length")
			}
			return []string{p.Masked().String()}, nil
		}
		return nil, errors.New("unexpected SSH nft set value")
	}
	switch v := value.(type) {
	case string:
		if key == "ip" || key == "ip6" {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, err
			}
			return []string{netip.PrefixFrom(a, a.BitLen()).String()}, nil
		}
		return []string{v}, nil
	case float64:
		if key == "ports" && v >= 1 && v <= 65535 && v == float64(int(v)) {
			return []string{strconv.Itoa(int(v))}, nil
		}
	}
	return nil, errors.New("invalid SSH nft match value")
}

func expectedSSHFirewall(sources, ports []string) ([]string, error) {
	v4, v6, err := normalizedSSHSources(sources)
	if err != nil {
		return nil, err
	}
	ports = append([]string(nil), ports...)
	sort.Strings(ports)
	portText := strings.Join(ports, ",")
	result := []string{"interface=lo;accept", "state=established,related;accept"}
	if len(v4) > 0 {
		result = append(result, "ip="+strings.Join(v4, ",")+";ports="+portText+";accept")
	}
	if len(v6) > 0 {
		result = append(result, "ip6="+strings.Join(v6, ",")+";ports="+portText+";accept")
	}
	return append(result, "ports="+portText+";drop"), nil
}

func normalizedSSHSources(sources []string) ([]string, []string, error) {
	var prefixes []netip.Prefix
	for _, source := range sources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			addr, addrErr := netip.ParseAddr(source)
			if addrErr != nil || addr.Zone() != "" {
				return nil, nil, fmt.Errorf("SSH source must be an IP or CIDR without an interface zone: %s", source)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() == prefixes[j].Bits() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	var kept []netip.Prefix
	var v4, v6 []string
	for _, prefix := range prefixes {
		covered := false
		for _, outer := range kept {
			if outer.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		kept = append(kept, prefix)
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

func (m *Manager) validateSSHFirewall(ctx context.Context, sources []string) error {
	ports, err := m.sshListeningPorts(ctx)
	if err != nil {
		return err
	}
	want, err := expectedSSHFirewall(sources, ports)
	if err != nil {
		return err
	}
	state, err := m.readSSHFirewall(ctx)
	if err != nil {
		return err
	}
	if !state.present || !state.owned || strings.Join(state.rules, "\n") != strings.Join(want, "\n") {
		return sshPolicyMismatch("SSH nft rules differ from requested sources, ports, established-session or drop rules")
	}
	if out, err := m.Runner.Run(ctx, "systemctl", "is-enabled", "anquan-ssh-allow.service"); err != nil || strings.TrimSpace(out) != "enabled" {
		return sshPolicyMismatch("SSH source restriction service is not enabled for boot")
	}
	return nil
}

func (m *Manager) reconcileSSHFirewall(ctx context.Context, previous, next manifest) error {
	state, err := m.readSSHFirewall(ctx)
	if err != nil && !state.owned {
		return err
	}
	if state.present && !state.owned {
		// Upgrade only an exact legacy table proven by this installation's old
		// owned file. A same-name external or drifted unmarked table is never deleted.
		if !previous.Firewall || previous.Files[firewallConfigPath] == "" {
			return errors.New("SSH nft table exists without Agent ownership")
		}
		data, e := os.ReadFile(m.path(firewallConfigPath))
		if e != nil || hashString(string(data)) != previous.Files[firewallConfigPath] {
			var journal transactionJournal
			if readPrivateJSON(m.journalPath(), "security-transaction", &journal) == nil {
				for _, snapshot := range journal.Before {
					if snapshot.Path == firewallConfigPath && snapshot.Exists && hashString(string(snapshot.Data)) == previous.Files[firewallConfigPath] {
						data, e = snapshot.Data, nil
						break
					}
				}
			}
		}
		if e != nil || hashString(string(data)) != previous.Files[firewallConfigPath] {
			return errors.New("cannot prove ownership of the existing unmarked SSH nft table")
		}
		legacy, err := expectedSSHFirewallFromFile(string(data))
		if err != nil || strings.Join(legacy, "\n") != strings.Join(state.rules, "\n") {
			return errors.New("unmarked SSH nft table differs from the owned legacy configuration")
		}
	}
	if next.Firewall {
		if _, err := m.Runner.Run(ctx, "nft", "-f", m.path(firewallConfigPath)); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "enable", "anquan-ssh-allow.service"); err != nil {
			return err
		}
		data, err := os.ReadFile(m.path(firewallConfigPath))
		if err != nil {
			return err
		}
		want, err := expectedSSHFirewallFromFile(string(data))
		if err != nil {
			return err
		}
		applied, err := m.readSSHFirewall(ctx)
		if err != nil {
			return err
		}
		legacyOwned := !strings.Contains(string(data), sshFirewallMarker) && next.Files[firewallConfigPath] == hashString(string(data))
		if (!applied.owned && !legacyOwned) || strings.Join(want, "\n") != strings.Join(applied.rules, "\n") {
			return errors.New("SSH nft batch did not produce the requested runtime rules")
		}
		return nil
	}
	if previous.Firewall {
		original := previous.FirewallOriginalUnitState
		if original == "enabled" {
			if _, err := m.Runner.Run(ctx, "systemctl", "enable", "anquan-ssh-allow.service"); err != nil {
				return err
			}
		} else {
			if _, err := m.Runner.Run(ctx, "systemctl", "disable", "anquan-ssh-allow.service"); err != nil {
				// A transaction may already have removed our unit file.
				current, checkErr := m.sshFirewallUnitState(ctx)
				if checkErr != nil || current == "enabled" || current == "enabled-runtime" {
					return err
				}
			}
			if original == "enabled-runtime" {
				if _, err := m.Runner.Run(ctx, "systemctl", "enable", "--runtime", "anquan-ssh-allow.service"); err != nil {
					return err
				}
			}
		}
		if state.present {
			_, err = m.Runner.Run(ctx, "nft", "delete", "table", "inet", "anquan_ssh")
			return err
		}
	}
	return nil
}

func expectedSSHFirewallFromFile(data string) ([]string, error) {
	var sources, ports []string
	sourcePattern := regexp.MustCompile(`(?m)^  ip6? saddr \{ ([^}]+) \} tcp dport \{ ([^}]+) \} accept$`)
	for _, match := range sourcePattern.FindAllStringSubmatch(data, -1) {
		for _, v := range strings.Split(match[1], ",") {
			sources = append(sources, strings.TrimSpace(v))
		}
		if ports == nil {
			for _, v := range strings.Split(match[2], ",") {
				ports = append(ports, strings.TrimSpace(v))
			}
		}
	}
	if len(sources) == 0 || len(ports) == 0 {
		return nil, errors.New("unrecognized managed SSH firewall file")
	}
	return expectedSSHFirewall(sources, ports)
}
