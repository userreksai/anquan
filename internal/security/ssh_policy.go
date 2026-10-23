package security

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var strongSSHAlgorithms = map[string][]string{
	"ciphers":                  {"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"},
	"macs":                     {"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"},
	"kexalgorithms":            {"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512"},
	"hostkeyalgorithms":        {"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"},
	"pubkeyacceptedalgorithms": {"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"},
}

func (m *Manager) sshExpectedSettings(ctx context.Context) (map[string]string, error) {
	s := m.Config.Policies.SSH
	want := map[string]string{}
	if s.PasswordAuthentication != "" {
		want["passwordauthentication"] = s.PasswordAuthentication
	}
	if s.PasswordAuthentication == "no" {
		want["kbdinteractiveauthentication"] = "no"
	}
	if s.PermitRootLogin != "" {
		want["permitrootlogin"] = s.PermitRootLogin
	}
	if len(s.AllowUsers) > 0 {
		want["allowusers"] = strings.Join(s.AllowUsers, " ")
	}
	if s.DisableForwarding {
		for _, k := range []string{"allowtcpforwarding", "allowagentforwarding", "allowstreamlocalforwarding", "x11forwarding", "permittunnel"} {
			want[k] = "no"
		}
		want["disableforwarding"] = "yes"
		want["permitopen"], want["permitlisten"] = "none", "none"
	}
	if s.StrongCrypto {
		for _, k := range sortedKeys(strongSSHAlgorithms) {
			query := map[string]string{"ciphers": "cipher", "macs": "mac", "kexalgorithms": "kex", "hostkeyalgorithms": "key-sig", "pubkeyacceptedalgorithms": "key-sig"}[k]
			out, err := m.Runner.Run(ctx, "ssh", "-Q", query)
			if err != nil {
				return nil, fmt.Errorf("query supported SSH %s: %w", k, err)
			}
			supported := map[string]bool{}
			for _, v := range strings.Fields(out) {
				supported[v] = true
			}
			var selected []string
			for _, v := range strongSSHAlgorithms[k] {
				if supported[v] {
					selected = append(selected, v)
				}
			}
			if len(selected) == 0 {
				return nil, fmt.Errorf("sshd host has no supported approved %s", k)
			}
			want[k] = strings.Join(selected, ",")
		}
	}
	return want, nil
}

// A service's actual argv, rather than its unexpanded systemd ExecStart template,
// establishes which configuration is being checked. Unknown overrides fail closed.
func (m *Manager) sshRuntime(ctx context.Context) (string, string, error) {
	for _, socket := range []string{"sshd.socket", "ssh.socket"} {
		if _, err := m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", socket); err == nil {
			return "", "", errors.New("SSH socket activation is not supported by policy enforcement; verify the listening service explicitly")
		}
	}
	for _, service := range []string{"sshd", "ssh"} {
		if _, err := m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", service); err != nil {
			continue
		}
		out, err := m.Runner.Run(ctx, "systemctl", "show", "--property=MainPID", "--value", service)
		if err != nil {
			return "", "", err
		}
		pid := strings.TrimSpace(out)
		n, err := strconv.Atoi(pid)
		if err != nil || n <= 0 {
			return "", "", errors.New("cannot identify the active SSH listener process")
		}
		raw, err := os.ReadFile(m.path("/proc/" + pid + "/cmdline"))
		if err != nil {
			return "", "", fmt.Errorf("read active SSH command line: %w", err)
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if len(args) == 1 && strings.HasPrefix(args[0], "sshd: ") {
			title, _, found := strings.Cut(strings.TrimPrefix(args[0], "sshd: "), " [listener]")
			if !found {
				return "", "", errors.New("SSH listener command line is unavailable in its process title")
			}
			args = strings.Fields(title)
		}
		if len(args) == 0 || filepath.Base(args[0]) != "sshd" {
			return "", "", errors.New("active SSH service does not expose a supported sshd command line")
		}
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "-D", "-e":
			case "-f":
				i++
				if i >= len(args) || args[i] != "/etc/ssh/sshd_config" {
					return "", "", errors.New("SSH policy requires the standard sshd_config; custom -f is unsupported")
				}
			default:
				return "", "", fmt.Errorf("SSH policy cannot safely verify active sshd argument %q", args[i])
			}
		}
		return service, pid, nil
	}
	return "", "", errors.New("neither sshd nor ssh service is active")
}

func (m *Manager) desiredSSHFiles(ctx context.Context) (map[string]managedFile, error) {
	if _, _, err := m.sshRuntime(ctx); err != nil {
		return nil, err
	}
	if _, err := m.sshPolicyContexts(); err != nil {
		return nil, err
	}
	main, err := os.ReadFile(m.path("/etc/ssh/sshd_config"))
	if err != nil {
		return nil, err
	}
	include := false
	inMatch := false
	for _, line := range strings.Split(string(main), "\n") {
		v := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(v) == 0 {
			continue
		}
		if strings.EqualFold(v[0], "Match") {
			inMatch = true
		}
		if !inMatch && strings.EqualFold(v[0], "Include") {
			for _, p := range v[1:] {
				if strings.Trim(p, "\"'") == "/etc/ssh/sshd_config.d/*.conf" {
					include = true
				}
			}
		}
	}
	if !include {
		return nil, errors.New("sshd_config must globally include /etc/ssh/sshd_config.d/*.conf")
	}
	for _, user := range m.Config.Policies.SSH.AllowUsers {
		if _, err := m.Runner.Run(ctx, "id", "-u", user); err != nil {
			return nil, fmt.Errorf("SSH allow_users account %s does not exist: %w", user, err)
		}
	}
	want, err := m.sshExpectedSettings(ctx)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# Managed by anquan\n")
	for _, k := range sortedKeys(want) {
		fmt.Fprintln(&b, k, want[k])
	}
	f := map[string]managedFile{sshConfigPath: {Data: []byte(b.String()), Mode: 0600}}
	if len(m.Config.Policies.SSH.AllowSources) > 0 {
		rules, err := m.firewallRules(ctx, m.Config.Policies.SSH.AllowSources)
		if err != nil {
			return nil, err
		}
		f[firewallConfigPath] = managedFile{Data: []byte(rules), Mode: 0600}
		nft, err := m.Runner.LookPath("nft")
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(nft, "/") || strings.ContainsAny(nft, " \t\r\n\"'\\%") {
			return nil, errors.New("nft executable must have an absolute path without systemd escape characters")
		}
		f[firewallUnitPath] = managedFile{Data: []byte("[Unit]\nDescription=Anquan SSH source restrictions\nAfter=network-pre.target\nBefore=sshd.service ssh.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=" + nft + " -f /etc/anquan/ssh-allow.nft\nExecReload=" + nft + " -f /etc/anquan/ssh-allow.nft\n[Install]\nWantedBy=multi-user.target\n"), Mode: 0644}
	}
	return f, nil
}

type sshPolicyContext struct{ user, addr, host, local, port string }

type sshPolicyMismatch string

func (e sshPolicyMismatch) Error() string { return string(e) }

// Match User/Address/LocalAddress/Host/LocalPort are partitioned into finite
// equivalence classes. Unsupported wildcard/group/exec predicates are rejected;
// sampling one allowed address must not masquerade as validating every client.
func (m *Manager) sshPolicyContexts() ([]sshPolicyContext, error) {
	users := map[string]bool{"root": true, "anquan-policy-probe": true}
	for _, u := range m.Config.Policies.SSH.AllowUsers {
		users[u] = true
	}
	hosts := map[string]bool{"anquan-policy-probe.invalid": true}
	ports := map[string]bool{"22": true}
	addresses := map[string]bool{"192.0.2.1": true, "2001:db8::1": true}
	locals := map[string]bool{"192.0.2.1": true, "2001:db8::1": true}
	seen := map[string]bool{}
	hasMatch := false
	var scan func(string, int) error
	scan = func(path string, depth int) error {
		if depth > 16 {
			return errors.New("SSH Include nesting exceeds 16")
		}
		if seen[path] {
			return nil
		}
		seen[path] = true
		if err := noSymlink(m.path(path)); err != nil {
			return err
		}
		data, err := os.ReadFile(m.path(path))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			v := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(v) == 0 {
				continue
			}
			if strings.EqualFold(v[0], "Include") {
				for _, pattern := range v[1:] {
					pattern = strings.Trim(pattern, "\"'")
					if !strings.HasPrefix(pattern, "/") {
						pattern = "/etc/ssh/" + pattern
					}
					matches, err := filepath.Glob(m.path(pattern))
					if err != nil {
						return err
					}
					for _, match := range matches {
						rel, err := filepath.Rel(m.RootDir, match)
						if err != nil {
							return err
						}
						if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
							return errors.New("SSH Include escapes the host root")
						}
						if err := scan("/"+filepath.ToSlash(rel), depth+1); err != nil {
							return err
						}
					}
				}
			}
			if !strings.EqualFold(v[0], "Match") {
				continue
			}
			hasMatch = true
			if len(v) == 2 && strings.EqualFold(v[1], "all") {
				continue
			}
			if len(v)%2 != 1 {
				return errors.New("unsupported SSH Match expression")
			}
			for i := 1; i < len(v); i += 2 {
				key := strings.ToLower(v[i])
				for _, token := range strings.Split(v[i+1], ",") {
					token = strings.TrimPrefix(token, "!")
					if token == "*" {
						continue
					}
					switch key {
					case "user":
						if !userPattern.MatchString(token) {
							return errors.New("SSH Match User wildcard cannot be exhaustively verified")
						}
						users[token] = true
					case "host":
						if strings.ContainsAny(token, "*?[] \t") {
							return errors.New("SSH Match Host wildcard cannot be exhaustively verified")
						}
						hosts[token] = true
					case "localport":
						n, e := strconv.Atoi(token)
						if e != nil || n < 1 || n > 65535 {
							return errors.New("invalid SSH Match LocalPort")
						}
						ports[token] = true
					case "address", "localaddress":
						p, e := netip.ParsePrefix(token)
						if e != nil {
							a, err := netip.ParseAddr(token)
							if err != nil {
								return errors.New("SSH Match address must be an IP or CIDR")
							}
							p = netip.PrefixFrom(a, a.BitLen())
						}
						set := addresses
						if key == "localaddress" {
							set = locals
						}
						p = p.Masked()
						set[p.Addr().String()] = true
						if prev := p.Addr().Prev(); prev.IsValid() {
							set[prev.String()] = true
						}
						last := p.Addr()
						for bit := p.Bits(); bit < last.BitLen(); bit++ {
							if last.Is4() {
								a := last.As4()
								a[bit/8] |= 1 << uint(7-bit%8)
								last = netip.AddrFrom4(a)
							} else {
								a := last.As16()
								a[bit/8] |= 1 << uint(7-bit%8)
								last = netip.AddrFrom16(a)
							}
						}
						if next := last.Next(); next.IsValid() {
							set[next.String()] = true
						}
					default:
						return fmt.Errorf("SSH Match %s is unsupported for exhaustive policy validation", v[i])
					}
				}
			}
		}
		return nil
	}
	if err := scan("/etc/ssh/sshd_config", 0); err != nil {
		return nil, err
	}
	if !hasMatch {
		return nil, nil
	}
	if len(users)*len(hosts)*len(ports)*len(addresses)*len(locals) > 512 {
		return nil, errors.New("SSH Match contexts exceed safe verification limit of 512")
	}
	var result []sshPolicyContext
	for _, u := range sortedKeys(users) {
		for _, a := range sortedKeys(addresses) {
			for _, h := range sortedKeys(hosts) {
				for _, l := range sortedKeys(locals) {
					for _, p := range sortedKeys(ports) {
						result = append(result, sshPolicyContext{u, a, h, l, p})
					}
				}
			}
		}
	}
	return result, nil
}

func sshSettingsMismatch(actual, want map[string]string) error {
	for _, key := range sortedKeys(want) {
		got, expected := actual[key], want[key]
		if key == "allowusers" {
			a, b := strings.Fields(got), strings.Fields(expected)
			sort.Strings(a)
			sort.Strings(b)
			got, expected = strings.Join(a, " "), strings.Join(b, " ")
		}
		if got != expected {
			return sshPolicyMismatch(fmt.Sprintf("effective SSH %s is %q, expected %q", key, actual[key], want[key]))
		}
	}
	return nil
}

func (m *Manager) validateSSHPolicy(ctx context.Context) error {
	if _, _, err := m.sshRuntime(ctx); err != nil {
		return err
	}
	if _, err := m.Runner.Run(ctx, "sshd", "-t"); err != nil {
		return err
	}
	want, err := m.sshExpectedSettings(ctx)
	if err != nil {
		return err
	}
	out, err := m.Runner.Run(ctx, "sshd", "-T")
	if err != nil {
		return err
	}
	if err := sshSettingsMismatch(parseSettings(out), want); err != nil {
		return err
	}
	global := parseSettings(out)
	if len(m.Config.Policies.SSH.AllowUsers) > 0 && (global["denyusers"] != "" || global["denygroups"] != "" || global["allowgroups"] != "") {
		return sshPolicyMismatch("SSH allowed users have additional DenyUsers/AllowGroups/DenyGroups restrictions; refusing to certify access")
	}
	contexts, err := m.sshPolicyContexts()
	if err != nil {
		return err
	}
	for _, c := range contexts {
		query := fmt.Sprintf("user=%s,addr=%s,host=%s,laddr=%s,lport=%s", c.user, c.addr, c.host, c.local, c.port)
		out, err := m.Runner.Run(ctx, "sshd", "-T", "-C", query)
		if err != nil {
			return fmt.Errorf("check SSH Match context %s: %w", query, err)
		}
		settings := parseSettings(out)
		if err := sshSettingsMismatch(settings, want); err != nil {
			return fmt.Errorf("SSH Match context %s: %w", query, err)
		}
		if containsString(m.Config.Policies.SSH.AllowUsers, c.user) && (settings["denyusers"] != "" || settings["denygroups"] != "" || settings["allowgroups"] != "") {
			return sshPolicyMismatch(fmt.Sprintf("SSH user %s has additional DenyUsers/AllowGroups/DenyGroups restrictions; refusing to certify access", c.user))
		}
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (m *Manager) checkSSHPolicy(ctx context.Context) []PolicyCheck {
	if !m.Config.Policies.SSH.Enabled {
		return nil
	}
	checks := []PolicyCheck{}
	want, expectedErr := m.sshExpectedSettings(ctx)
	if expectedErr == nil {
		out, readErr := m.Runner.Run(ctx, "sshd", "-T")
		actual := parseSettings(out)
		for _, key := range sortedKeys(want) {
			c := policyValueCheck("ssh."+key, want[key], actual[key], readErr)
			if readErr == nil {
				c.Compliant = sshSettingsMismatch(map[string]string{key: actual[key]}, map[string]string{key: want[key]}) == nil
			}
			checks = append(checks, c)
		}
	} else {
		checks = append(checks, policyValueCheck("ssh.supported_algorithms", "approved supported SSH algorithms", "unavailable", expectedErr))
	}
	err := m.validateSSHPolicy(ctx)
	check := PolicyCheck{Setting: "ssh.effective_policy", Expected: "active standard SSH service; requested values in every supported Match context", Actual: "verified", Compliant: err == nil}
	if err != nil {
		check.Actual = "mismatch or unverifiable"
		check.Message = err.Error()
		var mismatch sshPolicyMismatch
		if !errors.As(err, &mismatch) {
			check.Error = err.Error()
		}
	}
	checks = append(checks, check)
	if len(m.Config.Policies.SSH.AllowSources) > 0 {
		err = m.validateSSHFirewall(ctx, m.Config.Policies.SSH.AllowSources)
		c := PolicyCheck{Setting: "ssh.allow_sources", Expected: "exact managed rules and active listening ports", Actual: "verified", Compliant: err == nil}
		if err != nil {
			c.Actual = "mismatch or unverifiable"
			c.Message = err.Error()
			var mismatch sshPolicyMismatch
			if !errors.As(err, &mismatch) {
				c.Error = err.Error()
			}
		}
		checks = append(checks, c)
	}
	return checks
}

func (m *Manager) sshRuntimeDrift(ctx context.Context, previous manifest) (bool, error) {
	if !m.Config.Enabled || m.Config.Policies.Mode != "enforce" || !m.Config.Policies.SSH.Enabled {
		return false, nil
	}
	if err := m.validateSSHPolicy(ctx); err != nil {
		return true, nil
	}
	if len(m.Config.Policies.SSH.AllowSources) > 0 {
		if err := m.validateSSHFirewall(ctx, m.Config.Policies.SSH.AllowSources); err != nil {
			return true, nil
		}
	}
	return false, nil
}
