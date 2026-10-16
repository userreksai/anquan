package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const auditRulesPath = "/etc/audit/rules.d/60-anquan.rules"
const sudoConfigPath = "/etc/sudoers.d/90-anquan"
const sshConfigPath = "/etc/ssh/sshd_config.d/00-anquan.conf"
const sysctlConfigPath = "/etc/sysctl.d/90-anquan.conf"
const sessionConfigPath = "/etc/profile.d/90-anquan-session.sh"
const grubConfigPath = "/etc/grub.d/01_anquan"
const firewallConfigPath = "/etc/anquan/ssh-allow.nft"
const firewallUnitPath = "/etc/systemd/system/anquan-ssh-allow.service"

// Apply is synchronous. An error means the new configuration was not committed.
// Package installation is additive; configuration files are transactionally
// restored and previous services reloaded on a validation/activation failure.
func (m *Manager) Apply(ctx context.Context) ([]ComponentStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Config.Normalize()
	if err := m.Config.Validate(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" && m.RootDir == string(filepath.Separator) {
		m.statuses = []ComponentStatus{{Name: "security", Enabled: m.Config.Enabled, State: "unsupported", Message: "host security configuration requires Linux"}}
		return m.statuses, nil
	}
	if err := os.MkdirAll(m.OutputDir, 0700); err != nil {
		return nil, err
	}
	previous, err := m.loadManifest()
	if err != nil {
		return nil, fmt.Errorf("read security manifest: %w", err)
	}
	var interrupted transactionJournal
	if err = readPrivateJSON(m.journalPath(), "security-transaction", &interrupted); err == nil {
		if err = m.restore(interrupted.Before); err != nil {
			return nil, fmt.Errorf("recover interrupted security transaction: %w", err)
		}
		if err = m.activate(ctx, interrupted.Next, interrupted.Previous, interrupted.Dirty); err != nil {
			return nil, fmt.Errorf("recover previous security services: %w", err)
		}
		previous = interrupted.Previous
		if err = writePrivateJSON(m.manifestPath(), "security-managed", previous); err != nil {
			return nil, err
		}
		if err = os.Remove(m.journalPath()); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read security transaction: %w", err)
	}
	if m.Config.Enabled {
		if m.Config.Auditd.Enabled {
			if err = m.ensurePackage(ctx, "auditctl", "auditd", "audit"); err != nil {
				return m.failed("auditd", err)
			}
		}
		if m.Config.Sudo.Enabled {
			if err = m.ensurePackage(ctx, "sudo", "sudo", "sudo"); err != nil {
				return m.failed("sudo", err)
			}
		}
		if m.Config.Tetragon.Enabled {
			if _, err = m.Runner.LookPath("tetragon"); err != nil {
				if !m.Config.InstallMissing {
					return m.failed("tetragon", errors.New("Tetragon missing and install_missing is false"))
				}
				if err = m.installTetragon(ctx); err != nil {
					return m.failed("tetragon", err)
				}
			}
		}
		if m.Config.Policies.Mode == "enforce" && len(m.Config.Policies.SSH.AllowSources) > 0 && m.Config.Policies.SSH.Enabled {
			if err = m.ensurePackage(ctx, "nft", "nftables", "nftables"); err != nil {
				return m.failed("policies", err)
			}
		}
	}
	desired, options, err := m.desiredFiles(ctx)
	if err != nil {
		return m.failed("security", err)
	}
	next := manifest{Files: map[string]string{}, Options: options, CtrlAltDelMasked: m.Config.Enabled && m.Config.Policies.Mode == "enforce" && m.Config.Policies.DisableCtrlAltDel, Firewall: desired[firewallConfigPath].Data != nil}
	for p, f := range desired {
		next.Files[p] = hashString(string(f.Data))
	}
	next.CtrlAltDelOriginallyMasked = previous.CtrlAltDelOriginallyMasked
	if next.CtrlAltDelMasked && !previous.CtrlAltDelMasked {
		out, _ := m.Runner.Run(ctx, "systemctl", "is-enabled", "ctrl-alt-del.target")
		next.CtrlAltDelOriginallyMasked = strings.TrimSpace(out) == "masked"
	}
	if rules, ok := desired[auditRulesPath]; ok {
		next.AuditKeys = auditRuleKeys(string(rules.Data))
	}
	next.Sysctl = map[string]string{}
	next.SysctlOriginal = map[string]string{}
	if desired[sysctlConfigPath].Data != nil {
		for _, k := range sortedKeys(m.Config.Policies.Sysctl) {
			next.Sysctl[k] = m.Config.Policies.Sysctl[k]
			v, ok := previous.SysctlOriginal[k]
			if !ok {
				out, e := m.Runner.Run(ctx, "sysctl", "-n", k)
				if e != nil {
					return m.failed("policies", e)
				}
				v = strings.TrimSpace(out)
			}
			next.SysctlOriginal[k] = v
		}
	}
	equal := manifestsEqual(previous, next)
	dirty := map[string]bool{}
	for p, f := range desired {
		info, e := os.Stat(m.path(p))
		b, err := os.ReadFile(m.path(p))
		if e != nil || err != nil || !bytes.Equal(b, f.Data) || info.Mode().Perm() != f.Mode {
			equal = false
			dirty[p] = true
		}
	}
	if equal {
		m.appliedAt = previous.AppliedAt
		m.statuses = m.baseStatuses(ctx)
		return append([]ComponentStatus(nil), m.statuses...), nil
	}
	// Every path belongs to this module. Do not adopt or delete pre-existing
	// administrator drop-ins merely because they happen to use the same name.
	for p := range desired {
		if previous.Files[p] == "" {
			if _, e := os.Lstat(m.path(p)); e == nil {
				return m.failed("security", fmt.Errorf("managed path %s already exists without agent ownership", p))
			} else if !os.IsNotExist(e) {
				return m.failed("security", e)
			}
		}
	}
	tx := &transaction{manager: m, touched: map[string]bool{}, previous: previous, next: next, dirty: dirty}
	// Save runtime sysctl values before the first write, so rollback restores the
	// actual running values rather than reapplying unrelated system files.
	if err = tx.save(); err != nil {
		return m.failed("security", err)
	}
	rollback := func(cause error) ([]ComponentStatus, error) {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		rerr := m.restore(tx.before)
		rerr = errors.Join(rerr, m.activate(rollbackCtx, next, previous, dirty))
		if rerr == nil {
			_ = os.Remove(m.journalPath())
		}
		return m.failed("security", errors.Join(cause, rerr))
	}
	for _, p := range sortedKeys(previous.Files) {
		if _, ok := desired[p]; !ok {
			if err = tx.change(p, nil); err != nil {
				return rollback(err)
			}
		}
	}
	for _, p := range sortedKeys(desired) {
		f := desired[p]
		existing, e := os.ReadFile(m.path(p))
		info, statErr := os.Stat(m.path(p))
		if e == nil && statErr == nil && bytes.Equal(existing, f.Data) && info.Mode().Perm() == f.Mode {
			continue
		}
		if err = tx.change(p, &f); err != nil {
			return rollback(err)
		}
	}
	if err = m.validateFiles(ctx, desired); err != nil {
		return rollback(err)
	}
	if err = m.activate(ctx, previous, next, dirty); err != nil {
		return rollback(err)
	}
	next.AppliedAt = timePtr()
	if err = writePrivateJSON(m.manifestPath(), "security-managed", next); err != nil {
		return rollback(err)
	}
	if err = os.Remove(m.journalPath()); err != nil && !os.IsNotExist(err) {
		return m.failed("security", err)
	}
	m.appliedAt = next.AppliedAt
	m.statuses = m.baseStatuses(ctx)
	return append([]ComponentStatus(nil), m.statuses...), nil
}
func timePtr() *time.Time { t := time.Now().UTC(); return &t }
func (m *Manager) failed(name string, err error) ([]ComponentStatus, error) {
	m.statuses = []ComponentStatus{{Name: name, Enabled: m.Config.Enabled, State: "error", Message: err.Error(), ConfigHash: configHash(m.Config)}}
	return m.statuses, err
}
func (m *Manager) baseStatuses(ctx context.Context) []ComponentStatus {
	s := []ComponentStatus{m.status(ctx, "auditd", m.Config.Enabled && m.Config.Auditd.Enabled), m.status(ctx, "tetragon", m.Config.Enabled && m.Config.Tetragon.Enabled), m.status(ctx, "sudo", m.Config.Enabled && m.Config.Sudo.Enabled), m.status(ctx, "policies", m.Config.Enabled)}
	for i := range s {
		s[i].AppliedAt = m.appliedAt
		s[i].ConfigHash = configHash(m.Config)
		if s[i].Name == "policies" && s[i].State != "drift" && m.Config.Enabled && m.Config.Policies.Mode == "enforce" {
			s[i].State = "applied"
			s[i].Message = "typed policy configuration applied and validated"
		}
	}
	return s
}
func manifestsEqual(a, b manifest) bool {
	if len(a.Files) != len(b.Files) || a.CtrlAltDelMasked != b.CtrlAltDelMasked || a.Firewall != b.Firewall {
		return false
	}
	for k, v := range a.Files {
		if b.Files[k] != v {
			return false
		}
	}
	return true
}
func (m *Manager) ensurePackage(ctx context.Context, binary, deb, rpm string) error {
	if _, err := m.Runner.LookPath(binary); err == nil {
		return nil
	}
	if !m.Config.InstallMissing {
		return fmt.Errorf("%s is missing; set install_missing to install it", binary)
	}
	for _, pkg := range []string{"apt-get", "dnf", "yum"} {
		if _, err := m.Runner.LookPath(pkg); err == nil {
			args := []string{"install", "-y", rpm}
			if pkg == "apt-get" {
				if _, err = m.Runner.Run(ctx, pkg, "update"); err != nil {
					return err
				}
				args = []string{"install", "-y", "--no-install-recommends", deb}
			}
			if _, err = m.Runner.Run(ctx, pkg, args...); err != nil {
				return err
			}
			if _, err = m.Runner.LookPath(binary); err != nil {
				return fmt.Errorf("package installed but executable %s is still missing", binary)
			}
			return nil
		}
	}
	return errors.New("automatic installation supports apt-get, dnf or yum; install the component using your distribution package manager")
}
func (m *Manager) desiredFiles(ctx context.Context) (map[string]managedFile, []string, error) {
	f := map[string]managedFile{}
	options := []string{}
	add := func(p, s string, mode os.FileMode) { f[p] = managedFile{[]byte(s), mode} }
	if !m.Config.Enabled {
		return f, options, nil
	}
	if m.Config.Auditd.Enabled {
		var b strings.Builder
		b.WriteString("# Managed by anquan. Other audit rule files are preserved.\n")
		if m.Config.Auditd.AuditExec {
			arch := "b64"
			if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
				arch = "b32"
			}
			fmt.Fprintf(&b, "-a always,exit -F arch=%s -S execve,execveat -F auid!=unset -k anquan_exec\n", arch)
			if runtime.GOARCH == "amd64" {
				b.WriteString("-a always,exit -F arch=b32 -S execve,execveat -F auid!=unset -k anquan_exec\n")
			}
		}
		for _, p := range m.Config.Auditd.WatchPaths {
			if _, err := os.Stat(m.path(p)); err != nil {
				return nil, nil, fmt.Errorf("audit watch %s: %w (create it or remove it from watch_paths)", p, err)
			}
			fmt.Fprintf(&b, "-w %s -p wa -k anquan_file\n", p)
		}
		for _, r := range m.Config.Auditd.Rules {
			b.WriteString(r)
			b.WriteByte('\n')
		}
		add(auditRulesPath, b.String(), 0600)
	}
	if m.Config.Sudo.Enabled {
		s := "# Managed by anquan. Existing sudoers rules remain in effect.\nDefaults logfile=\"/var/log/anquan-sudo.log\"\n"
		if m.Config.Sudo.IOLogging {
			s += "Defaults log_input,log_output\nDefaults iolog_dir=\"/var/log/anquan-sudo-io\"\nDefaults iolog_file=\"%{seq}\"\n"
		}
		if m.Config.Policies.Mode == "enforce" {
			for _, g := range m.Config.Sudo.Grants {
				runAs := g.RunAs
				if runAs == "" {
					runAs = "root"
				}
				if _, err := m.Runner.Run(ctx, "id", "-u", g.User); err != nil {
					return nil, nil, err
				}
				if _, err := m.Runner.Run(ctx, "id", "-u", runAs); err != nil {
					return nil, nil, err
				}
				tag := "PASSWD:"
				if g.NoPasswd {
					tag = "NOPASSWD:"
				}
				s += fmt.Sprintf("%s ALL=(%s) %s %s\n", g.User, runAs, tag, strings.Join(g.Commands, ", "))
			}
		}
		add(sudoConfigPath, s, 0440)
	}
	if m.Config.Tetragon.Enabled {
		opts, err := tetragonOptions(m.Config.Tetragon.Config)
		if err != nil {
			return nil, nil, err
		}
		opts["export-filename"] = "/var/log/tetragon/tetragon.log"
		opts["server-address"] = "unix:///var/run/tetragon/tetragon.sock"
		opts["health-server-address"] = ""
		opts["metrics-server"] = ""
		opts["export-file-compress"] = "false"
		opts["enable-k8s-api"] = "false"
		opts["export-file-max-size-mb"] = "20"
		opts["export-file-max-backups"] = "10"
		for _, k := range sortedKeys(opts) {
			add("/etc/anquan/tetragon.conf.d/"+k, opts[k]+"\n", 0600)
			options = append(options, k)
		}
		binary, err := m.Runner.LookPath("tetragon")
		if err != nil {
			return nil, nil, err
		}
		if strings.ContainsAny(binary, " \t\n\r\"") {
			return nil, nil, errors.New("Tetragon binary path cannot contain whitespace or quotes")
		}
		add("/etc/systemd/system/tetragon.service.d/90-anquan.conf", "[Service]\nExecStart=\nExecStart="+binary+" --config-dir=/etc/anquan/tetragon.conf.d\n", 0644)
		if m.Config.Tetragon.TracingPolicy != "" {
			add("/etc/tetragon/tetragon.tp.d/anquan.yaml", m.Config.Tetragon.TracingPolicy, 0600)
		}
	}
	if m.Config.Policies.Mode != "enforce" {
		return f, options, nil
	}
	p := m.Config.Policies
	if p.SSH.Enabled {
		main, err := os.ReadFile(m.path("/etc/ssh/sshd_config"))
		if err != nil {
			return nil, nil, err
		}
		include := false
		for _, line := range strings.Split(string(main), "\n") {
			v := strings.Fields(line)
			if len(v) > 1 && strings.EqualFold(v[0], "Include") {
				for _, pat := range v[1:] {
					if pat == "/etc/ssh/sshd_config.d/*.conf" {
						include = true
					}
				}
			}
		}
		if !include {
			return nil, nil, errors.New("sshd_config must include /etc/ssh/sshd_config.d/*.conf; refusing to replace the administrator's configuration")
		}
		var b strings.Builder
		b.WriteString("# Managed by anquan\n")
		if p.SSH.PasswordAuthentication != "" {
			fmt.Fprintln(&b, "PasswordAuthentication", p.SSH.PasswordAuthentication)
			if p.SSH.PasswordAuthentication == "no" {
				fmt.Fprintln(&b, "KbdInteractiveAuthentication no")
			}
		}
		if p.SSH.PermitRootLogin != "" {
			fmt.Fprintln(&b, "PermitRootLogin", p.SSH.PermitRootLogin)
		}
		if len(p.SSH.AllowUsers) > 0 {
			for _, u := range p.SSH.AllowUsers {
				if _, err = m.Runner.Run(ctx, "id", "-u", u); err != nil {
					return nil, nil, fmt.Errorf("SSH allow_users account %s does not exist: %w", u, err)
				}
			}
			fmt.Fprintln(&b, "AllowUsers", strings.Join(p.SSH.AllowUsers, " "))
		}
		add(sshConfigPath, b.String(), 0600)
		if len(p.SSH.AllowSources) > 0 {
			rules, err := m.firewallRules(ctx, p.SSH.AllowSources)
			if err != nil {
				return nil, nil, err
			}
			add(firewallConfigPath, rules, 0600)
			add(firewallUnitPath, "[Unit]\nDescription=Anquan SSH source restrictions\nAfter=network-pre.target\nBefore=sshd.service ssh.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/anquan/ssh-allow.nft\nExecReload=/usr/sbin/nft -f /etc/anquan/ssh-allow.nft\n[Install]\nWantedBy=multi-user.target\n", 0644)
		}
	}
	if len(p.Sysctl) > 0 {
		var b strings.Builder
		b.WriteString("# Managed by anquan\n")
		for _, k := range sortedKeys(p.Sysctl) {
			fmt.Fprintf(&b, "%s = %s\n", k, p.Sysctl[k])
		}
		add(sysctlConfigPath, b.String(), 0644)
	}
	if p.SessionTimeoutSeconds > 0 {
		add(sessionConfigPath, fmt.Sprintf("# Managed by anquan; applies to interactive Bash prompts.\nif [ -n \"${BASH_VERSION:-}\" ] && [ -n \"${PS1:-}\" ]; then\n  TMOUT=%d\n  readonly TMOUT\n  export TMOUT\nfi\n", p.SessionTimeoutSeconds), 0644)
	}
	if p.GRUB.Enabled {
		add(grubConfigPath, "#!/bin/sh\n# Managed by anquan. GRUB authentication may also protect restricted boot entries.\ncat <<'ANQUAN_GRUB_AUTH'\nset superusers=\"anquan-admin\"\nexport superusers\npassword_pbkdf2 anquan-admin "+p.GRUB.PasswordHash+"\nANQUAN_GRUB_AUTH\n", 0700)
	}
	sort.Strings(options)
	return f, options, nil
}
func (m *Manager) validateFiles(ctx context.Context, files map[string]managedFile) error {
	if _, ok := files[sudoConfigPath]; ok {
		if _, err := m.Runner.Run(ctx, "visudo", "-cf", m.path(sudoConfigPath)); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "visudo", "-c"); err != nil {
			return err
		}
	}
	if _, ok := files[sshConfigPath]; ok {
		if _, err := m.Runner.Run(ctx, "sshd", "-t"); err != nil {
			return err
		}
		out, err := m.Runner.Run(ctx, "sshd", "-T")
		if err != nil {
			return err
		}
		effective := parseSettings(out)
		s := m.Config.Policies.SSH
		if s.PasswordAuthentication != "" && effective["passwordauthentication"] != s.PasswordAuthentication {
			return errors.New("effective SSH PasswordAuthentication differs from requested value (earlier setting or Match block)")
		}
		if s.PermitRootLogin != "" && effective["permitrootlogin"] != s.PermitRootLogin {
			return errors.New("effective SSH PermitRootLogin differs from requested value")
		}
		if len(s.AllowUsers) > 0 && effective["allowusers"] != strings.Join(s.AllowUsers, " ") {
			return errors.New("effective SSH AllowUsers differs from requested users")
		}
	}
	if _, ok := files[firewallConfigPath]; ok {
		if _, err := m.Runner.Run(ctx, "nft", "-c", "-f", m.path(firewallConfigPath)); err != nil {
			return err
		}
	}
	return nil
}
func parseSettings(raw string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if i := strings.IndexAny(line, " \t"); i > 0 {
			k := strings.ToLower(line[:i])
			v := strings.TrimSpace(line[i:])
			if k == "permitrootlogin" && v == "without-password" {
				v = "prohibit-password"
			}
			if k == "port" && m[k] != "" {
				m[k] += " " + v
			} else {
				m[k] = v
			}
		}
	}
	return m
}
func (m *Manager) loadAudit(ctx context.Context) error {
	if _, err := os.Stat(m.path(auditRulesPath)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	// Runtime loading is restricted to this product's additive rules. The
	// distribution's boot-time loader picks up the persistent rules.d file.
	_, err := m.Runner.Run(ctx, "auditctl", "-R", m.path(auditRulesPath))
	return err
}
func (m *Manager) activate(ctx context.Context, previous, next manifest, dirty ...map[string]bool) error {
	changed := func(p string) bool { return previous.Files[p] != next.Files[p] || (len(dirty) > 0 && dirty[0][p]) }
	if changed(auditRulesPath) {
		if _, err := m.Runner.Run(ctx, "systemctl", "enable", "--now", "auditd"); err != nil && next.Files[auditRulesPath] != "" {
			return err
		}
		if out, err := m.Runner.Run(ctx, "auditctl", "-s"); err != nil {
			return err
		} else if strings.Contains(out, "enabled 2") {
			return errors.New("kernel audit policy is immutable; reboot with an editable policy before applying configuration")
		}
		for _, key := range previous.AuditKeys {
			if _, err := m.Runner.Run(ctx, "auditctl", "-D", "-k", key); err != nil {
				return err
			}
		}
		if err := m.loadAudit(ctx); err != nil {
			return err
		}
	}
	tetragonChanged := false
	for _, files := range []map[string]string{previous.Files, next.Files} {
		for p := range files {
			if (strings.Contains(p, "tetragon.conf.d/") || strings.Contains(p, "tetragon.tp.d/") || strings.Contains(p, "tetragon.service.d/")) && changed(p) {
				tetragonChanged = true
			}
		}
	}
	if tetragonChanged {
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if next.Files["/etc/systemd/system/tetragon.service.d/90-anquan.conf"] != "" {
			if _, err := m.Runner.Run(ctx, "systemctl", "enable", "tetragon"); err != nil {
				return err
			}
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "restart", "tetragon"); err != nil {
			return err
		}
	}
	if changed(firewallUnitPath) {
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if next.Firewall {
		if _, err := m.Runner.Run(ctx, "nft", "-f", m.path(firewallConfigPath)); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "enable", "anquan-ssh-allow.service"); err != nil {
			return err
		}
	} else if previous.Firewall {
		_, _ = m.Runner.Run(ctx, "systemctl", "disable", "anquan-ssh-allow.service")
		if _, err := m.Runner.Run(ctx, "nft", "delete", "table", "inet", "anquan_ssh"); err != nil {
			return err
		}
	}
	if changed(sshConfigPath) {
		if _, err := m.Runner.Run(ctx, "sshd", "-t"); err != nil {
			return err
		}
		if err := m.reloadSSH(ctx); err != nil {
			return err
		}
	}
	if changed(sysctlConfigPath) {
		keys := map[string]bool{}
		for k := range previous.Sysctl {
			keys[k] = true
		}
		for k := range next.Sysctl {
			keys[k] = true
		}
		for _, k := range sortedKeys(keys) {
			v, ok := next.Sysctl[k]
			if !ok {
				v = previous.SysctlOriginal[k]
			}
			if v != "" {
				if _, err := m.Runner.Run(ctx, "sysctl", "-w", k+"="+v); err != nil {
					return err
				}
			}
		}
	}
	if previous.CtrlAltDelMasked != next.CtrlAltDelMasked {
		action := "unmask"
		if next.CtrlAltDelMasked || previous.CtrlAltDelOriginallyMasked {
			action = "mask"
		}
		if _, err := m.Runner.Run(ctx, "systemctl", action, "ctrl-alt-del.target"); err != nil {
			return err
		}
	}
	if changed(grubConfigPath) {
		if err := m.updateGRUB(ctx); err != nil {
			return err
		}
	}
	return nil
}
func auditRuleKeys(raw string) []string {
	keys := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "-k" {
				keys[f[i+1]] = true
			}
		}
	}
	return sortedKeys(keys)
}
func (m *Manager) reloadSSH(ctx context.Context) error {
	for _, service := range []string{"sshd", "ssh"} {
		if _, err := m.Runner.Run(ctx, "systemctl", "is-active", "--quiet", service); err == nil {
			_, err = m.Runner.Run(ctx, "systemctl", "reload", service)
			return err
		}
	}
	return errors.New("neither sshd nor ssh service is active; refusing to report SSH configuration as applied")
}
func (m *Manager) updateGRUB(ctx context.Context) error {
	if _, err := m.Runner.LookPath("update-grub"); err == nil {
		_, err = m.Runner.Run(ctx, "update-grub")
		return err
	}
	return errors.New("GRUB enforcement currently supports distributions providing update-grub; firmware-specific grub2-mkconfig targets require manual integration")
}
