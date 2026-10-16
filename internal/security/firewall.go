package security

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func (m *Manager) firewallRules(ctx context.Context, sources []string) (string, error) {
	out, err := m.Runner.Run(ctx, "sshd", "-T")
	if err != nil {
		return "", err
	}
	settings := parseSettings(out)
	ports := strings.Fields(settings["port"])
	if len(ports) == 0 {
		return "", errors.New("cannot determine effective SSH listening ports")
	}
	for _, p := range ports {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid SSH listening port")
		}
	}
	v4, v6 := []string{}, []string{}
	for _, s := range sources {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			a, e := netip.ParseAddr(s)
			if e != nil {
				return "", e
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	var b strings.Builder
	// An nft batch is atomic. Adding the empty table first allows the same
	// script to replace our table when it exists and create it on first boot.
	b.WriteString("# Managed by anquan; does not flush other firewall tables.\ntable inet anquan_ssh {}\ndelete table inet anquan_ssh\ntable inet anquan_ssh {\n chain restrict_ssh {\n  type filter hook input priority -10; policy accept;\n  iifname \"lo\" accept\n  ct state established,related accept\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "  ip saddr { %s } tcp dport { %s } accept\n", strings.Join(v4, ", "), strings.Join(ports, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "  ip6 saddr { %s } tcp dport { %s } accept\n", strings.Join(v6, ", "), strings.Join(ports, ", "))
	}
	fmt.Fprintf(&b, "  tcp dport { %s } drop\n }\n}\n", strings.Join(ports, ", "))
	return b.String(), nil
}
