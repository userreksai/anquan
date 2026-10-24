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
func (m *Manager) Apply(ctx context.Context) (result []ComponentStatus, applyErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if applyErr == nil {
			m.applicationError = nil
			return
		}
		failure := ComponentStatus{Name: "security", Enabled: m.Config.Enabled, State: "error", Message: applyErr.Error(), ConfigHash: configHash(m.Config)}
		if len(result) == 1 && result[0].State == "error" {
			failure = result[0]
		}
		m.applicationError = &failure
	}()
	defer func() {
		if m.downloadProxy != nil {
			_ = m.downloadProxy.Close()
			m.downloadProxy = nil
		}
	}()
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
	_, manifestErr := os.Lstat(m.manifestPath())
	hadManifest := manifestErr == nil
	var interrupted transactionJournal
	if err = readPrivateJSON(m.journalPath(), "security-transaction", &interrupted); err == nil {
		if err = m.restore(interrupted.Before); err != nil {
			return nil, fmt.Errorf("recover interrupted security transaction: %w", err)
		}
		if err = m.trackLegacyAuditRules(&interrupted.Previous); err != nil {
			return nil, fmt.Errorf("recover previous audit ownership: %w", err)
		}
		restored := interrupted.Previous
		restored.AuditRules = cloneAuditRules(interrupted.Next.AuditRules)
		if !interrupted.Next.AuditRulesTracked {
			restored.AuditRules = cloneAuditRules(interrupted.Previous.AuditRules)
		}
		restored.AuditRulesTracked = true
		saveRecovery := func() error {
			interrupted.Next.AuditRules = restored.AuditRules
			interrupted.Next.AuditRulesTracked = true
			return writePrivateJSON(m.journalPath(), "security-transaction", interrupted)
		}
		recoveryCtx, bootErr := m.bootRecoveryContext(ctx, interrupted)
		if bootErr != nil {
			return nil, fmt.Errorf("recover previous boot configuration: %w", bootErr)
		}
		recoveryErr := m.activate(recoveryCtx, interrupted.Next, restored, interrupted.Dirty, saveRecovery)
		runtimeErr := m.restoreRuntime(ctx, interrupted.RuntimeSysctl, interrupted.RuntimeCADState)
		if err = errors.Join(recoveryErr, runtimeErr); err != nil {
			return nil, fmt.Errorf("recover previous security services and effective host values: %w", err)
		}
		previous = restored
		if err = writePrivateJSON(m.manifestPath(), "security-managed", previous); err != nil {
			return nil, err
		}
		if err = os.Remove(m.journalPath()); err != nil {
			return nil, err
		}
		hadManifest = true
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read security transaction: %w", err)
	}
	// Old manifests tracked only keys. Recover complete rules only from the
	// exact file whose ownership and contents that manifest proves.
	if err = m.trackLegacyAuditRules(&previous); err != nil {
		return m.failed("auditd", err)
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
		if m.Config.Policies.Mode == "enforce" && m.Config.Policies.SSH.Enabled && m.Config.Policies.SSH.StrongCrypto {
			if err = m.ensurePackage(ctx, "ssh", "openssh-client", "openssh-clients"); err != nil {
				return m.failed("policies", err)
			}
		}
		if m.Config.Policies.Mode == "enforce" && len(m.Config.Policies.SSH.AllowSources) > 0 && m.Config.Policies.SSH.Enabled {
			if err = m.ensurePackage(ctx, "nft", "nftables", "nftables"); err != nil {
				return m.failed("policies", err)
			}
			if err = m.ensurePackage(ctx, "ss", "iproute2", "iproute"); err != nil {
				return m.failed("policies", err)
			}
		}
	}
	desired, options, err := m.desiredFiles(ctx)
	if err != nil {
		return m.failed("security", err)
	}
	next := manifest{Files: map[string]string{}, ReferencedFiles: map[string]string{}, AuditRules: cloneAuditRules(previous.AuditRules), AuditRulesTracked: true, Options: options, CtrlAltDelMasked: m.Config.Enabled && m.Config.Policies.Mode == "enforce" && m.Config.Policies.DisableCtrlAltDel, Firewall: desired[firewallConfigPath].Data != nil}
	next.FirewallOriginalUnitState = previous.FirewallOriginalUnitState
	if next.Firewall && !previous.Firewall {
		state, stateErr := m.sshFirewallUnitState(ctx)
		if stateErr != nil {
			return m.failed("policies", stateErr)
		}
		next.FirewallOriginalUnitState = state
	}
	for p, f := range desired {
		next.Files[p] = hashString(string(f.Data))
	}
	// A missing ownership record is not permission to replace an existing file.
	// Reuse an exact match without acquiring ownership, including after state
	// loss. Keep this before the equality fast path so references are rechecked.
	for _, p := range sortedKeys(desired) {
		if previous.Files[p] != "" {
			continue
		}
		exists, err := m.referenceExistingFile(p, desired[p])
		if err != nil {
			return m.failed("security", err)
		}
		if exists {
			next.ReferencedFiles[p] = next.Files[p]
			delete(next.Files, p)
		}
	}
	next.CtrlAltDelOriginallyMasked = previous.CtrlAltDelOriginallyMasked
	next.CtrlAltDelOriginalState = previous.CtrlAltDelOriginalState
	if next.CtrlAltDelMasked && !previous.CtrlAltDelMasked {
		state, e := m.ctrlAltDelState(ctx)
		if e != nil {
			return m.failed("policies", e)
		}
		next.CtrlAltDelOriginallyMasked = state == "masked" || state == "masked-runtime"
		next.CtrlAltDelOriginalState = state
	}
	next.Sysctl = map[string]string{}
	next.SysctlOriginal = map[string]string{}
	if desired[sysctlConfigPath].Data != nil {
		for _, k := range sortedKeys(m.Config.Policies.Sysctl) {
			next.Sysctl[k] = m.Config.Policies.Sysctl[k]
			v, ok := previous.SysctlOriginal[k]
			if !ok {
				out, e := m.readSysctl(ctx, k)
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
		if e != nil || err != nil || !bytes.Equal(b, f.Data) || !managedModeMatches(info.Mode(), f.Mode) {
			equal = false
			dirty[p] = true
		}
	}
	// File equality does not imply runtime equality. Reapplying the same
	// selected policy must repair values changed since the last successful ACK.
	runtimeSysctl := map[string]string{}
	keys := map[string]bool{}
	for key := range previous.Sysctl {
		keys[key] = true
	}
	for key := range next.Sysctl {
		keys[key] = true
	}
	for _, key := range sortedKeys(keys) {
		actual, e := m.readSysctl(ctx, key)
		if e != nil {
			return m.failed("policies", e)
		}
		runtimeSysctl[key] = actual
		if want, selected := next.Sysctl[key]; selected && actual != normalizePolicyValue(want) {
			equal, dirty[sysctlConfigPath] = false, true
		}
	}
	var runtimeCADState *string
	if previous.CtrlAltDelMasked || next.CtrlAltDelMasked {
		if err := m.validateCtrlAltDelPaths(); err != nil {
			return m.failed("policies", err)
		}
		state, e := m.ctrlAltDelState(ctx)
		if e != nil {
			return m.failed("policies", e)
		}
		runtimeCADState = &state
		if next.CtrlAltDelMasked {
			action, e := m.ctrlAltDelBurstAction(ctx)
			if e != nil {
				return m.failed("policies", e)
			}
			if state != "masked" || action != "none" {
				equal, dirty[ctrlAltDelConfigPath] = false, true
			}
		}
	}
	if drift, e := m.sshRuntimeDrift(ctx, previous); e != nil {
		return m.failed("policies", e)
	} else if drift {
		equal, dirty[sshConfigPath] = false, true
		if next.Firewall {
			dirty[firewallConfigPath] = true
		}
	}
	if m.Config.Enabled && m.Config.Policies.Mode == "enforce" && m.Config.Policies.GRUB.Enabled {
		if err := m.validateBootPolicy(ctx); err != nil {
			equal, dirty[grubConfigPath] = false, true
		}
	}
	// A directory's audit tree can disappear with its inode even when it is
	// recreated before the next scan. Recheck the live rules on every cron
	// reconciliation, including when the generated file has identical bytes.
	if m.hasCronAuditWatches() {
		equal, dirty[auditRulesPath] = false, true
	}
	if equal {
		if err = m.validateFiles(ctx, desired); err != nil {
			return m.failed("policies", err)
		}
		if m.Config.Enabled && m.Config.Policies.Mode == "enforce" {
			if err = m.validateSessionPolicy(ctx); err != nil {
				return m.failed("policies", err)
			}
			if err = m.validateBootPolicy(ctx); err != nil {
				return m.failed("policies", err)
			}
			if err = m.validateEffectivePolicies(ctx); err != nil {
				return m.failed("policies", err)
			}
		}
		m.appliedAt = previous.AppliedAt
		m.statuses = m.baseStatuses(ctx)
		return append([]ComponentStatus(nil), m.statuses...), nil
	}
	tx := &transaction{manager: m, touched: map[string]bool{}, previous: previous, next: next, dirty: dirty, runtimeSysctl: runtimeSysctl, runtimeCADState: runtimeCADState}
	// Save runtime sysctl values before the first write, so rollback restores the
	// actual running values rather than reapplying unrelated system files.
	if err = m.snapshotBootFiles(tx, previous, next); err != nil {
		return m.failed("policies", err)
	}
	if err = tx.save(); err != nil {
		return m.failed("security", err)
	}
	rollback := func(cause error) ([]ComponentStatus, error) {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		rerr := m.restore(tx.before)
		restored := previous
		restored.AuditRules = cloneAuditRules(next.AuditRules)
		restored.AuditRulesTracked = true
		tx.next.AuditRules = restored.AuditRules
		if rerr == nil {
			rerr = m.activate(withBootRollback(rollbackCtx), next, restored, dirty, tx.save)
		}
		rerr = errors.Join(rerr, m.restoreRuntime(rollbackCtx, tx.runtimeSysctl, tx.runtimeCADState))
		if rerr == nil && (hadManifest || len(restored.AuditRules) > 0) {
			rerr = writePrivateJSON(m.manifestPath(), "security-managed", restored)
		}
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
		if next.ReferencedFiles[p] != "" {
			exists, err := m.referenceExistingFile(p, f)
			if err != nil {
				return rollback(err)
			}
			if !exists {
				return rollback(fmt.Errorf("referenced configuration disappeared during apply: %s", p))
			}
			continue
		}
		if previous.Files[p] == "" {
			// The file may have appeared since preflight. Do not grant ownership
			// or overwrite it just because the earlier check saw no file.
			exists, err := m.referenceExistingFile(p, f)
			if err != nil {
				return rollback(err)
			}
			if exists {
				next.ReferencedFiles[p] = next.Files[p]
				delete(next.Files, p)
				if err := tx.save(); err != nil {
					return rollback(err)
				}
				continue
			}
		}
		existing, e := os.ReadFile(m.path(p))
		info, statErr := os.Stat(m.path(p))
		if e == nil && statErr == nil && bytes.Equal(existing, f.Data) && managedModeMatches(info.Mode(), f.Mode) {
			continue
		}
		if err = tx.change(p, &f); err != nil {
			return rollback(err)
		}
	}
	if err = m.validateFiles(ctx, desired); err != nil {
		return rollback(err)
	}
	if err = m.activate(ctx, previous, next, dirty, tx.save); err != nil {
		return rollback(err)
	}
	if m.Config.Enabled && m.Config.Policies.Mode == "enforce" {
		if err = m.validateSessionPolicy(ctx); err != nil {
			return rollback(err)
		}
		if err = m.validateBootPolicy(ctx); err != nil {
			return rollback(err)
		}
		if err = m.validateEffectivePolicies(ctx); err != nil {
			return rollback(err)
		}
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
	}
	return s
}
func manifestsEqual(a, b manifest) bool {
	if len(a.Files) != len(b.Files) || len(a.ReferencedFiles) != len(b.ReferencedFiles) || a.CtrlAltDelMasked != b.CtrlAltDelMasked || a.Firewall != b.Firewall {
		return false
	}
	for k, v := range a.Files {
		if b.Files[k] != v {
			return false
		}
	}
	for p, referenced := range a.ReferencedFiles {
		if b.ReferencedFiles[p] != referenced {
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
			proxy, proxyErr := m.packageProxy(ctx)
			if proxyErr != nil {
				return proxyErr
			}
			ctx = relayCommandContext(ctx, proxy)
			args := []string{"install", "-y", rpm}
			if pkg == "apt-get" {
				options, optionErr := m.aptProxyOptions(ctx, proxy)
				if optionErr != nil {
					return optionErr
				}
				if _, err = m.runAPT(ctx, append(options, "update")...); err != nil {
					return err
				}
				args = append(options, "install", "-y", "--no-install-recommends", deb)
			} else if proxy != "" {
				// Per-repository proxy=_none_ overrides the main setting. Override
				// every repository too and disable plugins with independent networking.
				args = append([]string{"--noplugins", "--setopt=proxy=" + proxy, "--setopt=*.proxy=" + proxy}, args...)
			}
			if pkg == "apt-get" {
				_, err = m.runAPT(ctx, args...)
			} else {
				_, err = m.Runner.Run(ctx, pkg, args...)
			}
			if err != nil {
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
				if IsCronPath(p) && os.IsNotExist(err) {
					continue
				}
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
		if m.Config.Policies.Mode == "enforce" {
			if err := m.validateSudoGrantAuthentication(); err != nil {
				return nil, nil, err
			}
		}
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
		if m.Config.Policies.Mode == "enforce" && len(m.sudoPolicyUsers()) > 0 {
			if err := m.validateSudoRestrictionOrder(); err != nil {
				return nil, nil, err
			}
			if err := m.validateSudoRestrictedAccounts(ctx); err != nil {
				return nil, nil, err
			}
			add(sudoRestrictionPath, m.sudoRestrictionFile(), 0440)
		}
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
		sshFiles, err := m.desiredSSHFiles(ctx)
		if err != nil {
			return nil, nil, err
		}
		for path, file := range sshFiles {
			f[path] = file
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
		add(sessionConfigPath, sessionPolicyScript(p.SessionTimeoutSeconds), 0644)
	}
	if p.DisableCtrlAltDel {
		add(ctrlAltDelConfigPath, "# Managed by anquan\n[Manager]\nCtrlAltDelBurstAction=none\n", 0644)
	}
	if p.GRUB.Enabled {
		if err := m.validateBootEnvironment(); err != nil {
			return nil, nil, err
		}
		add(grubConfigPath, bootAuthenticationScript(p.GRUB.PasswordHash), 0700)
		if p.GRUB.ProtectSingleUser {
			add(bootRecoveryConfigPath, "# Managed by anquan; recovery entries must be generated and authenticated.\nGRUB_DISABLE_RECOVERY=false\n", 0644)
		}
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
		if _, ok := files[sudoRestrictionPath]; ok {
			if err := m.validateSudoRestrictions(ctx); err != nil {
				return err
			}
		}
	}
	if _, ok := files[sshConfigPath]; ok {
		if err := m.validateSSHPolicy(ctx); err != nil {
			return err
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
func (m *Manager) activate(ctx context.Context, previous, next manifest, dirty map[string]bool, save func() error) error {
	previousFiles, nextFiles := previous.configuredFiles(), next.configuredFiles()
	changed := func(p string) bool { return previousFiles[p] != nextFiles[p] || dirty[p] }
	if changed(auditRulesPath) {
		if _, err := m.Runner.Run(ctx, "systemctl", "enable", "--now", "auditd"); err != nil && nextFiles[auditRulesPath] != "" {
			return err
		}
		if out, err := m.Runner.Run(ctx, "auditctl", "-s"); err != nil {
			return err
		} else if strings.Contains(out, "enabled 2") {
			return errors.New("kernel audit policy is immutable; reboot with an editable policy before applying configuration")
		}
		if err := m.reconcileAudit(ctx, next.AuditRules, save, nextFiles[auditRulesPath] != ""); err != nil {
			return err
		}
	}
	tetragonChanged := false
	for _, files := range []map[string]string{previousFiles, nextFiles} {
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
		if nextFiles["/etc/systemd/system/tetragon.service.d/90-anquan.conf"] != "" {
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
	if previous.Firewall || next.Firewall {
		if err := m.reconcileSSHFirewall(ctx, previous, next); err != nil {
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
				if err := m.writeSysctl(ctx, k, v); err != nil {
					return err
				}
			}
		}
	}
	if changed(ctrlAltDelConfigPath) {
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reexec"); err != nil {
			return err
		}
	}
	if previous.CtrlAltDelMasked != next.CtrlAltDelMasked || dirty[ctrlAltDelConfigPath] {
		state := previous.CtrlAltDelOriginalState
		if state == "" {
			state = "static"
			if previous.CtrlAltDelOriginallyMasked {
				state = "masked"
			}
		}
		if next.CtrlAltDelMasked {
			state = "masked"
		}
		if err := m.setCtrlAltDelState(ctx, state); err != nil {
			return err
		}
	}
	if next.CtrlAltDelMasked {
		action, err := m.ctrlAltDelBurstAction(ctx)
		if err != nil {
			return err
		}
		if action != "none" {
			return fmt.Errorf("CtrlAltDelBurstAction did not take effect: expected none, actual %q", action)
		}
	}
	if !isBootRollback(ctx) && (changed(grubConfigPath) || changed(bootRecoveryConfigPath)) {
		if err := m.updateGRUB(ctx); err != nil {
			return err
		}
		if nextFiles[grubConfigPath] != "" {
			if err := m.validateGeneratedBootFiles(ctx, nextFiles[bootRecoveryConfigPath] != ""); err != nil {
				return err
			}
		} else if previous.Files[grubConfigPath] != "" {
			if err := m.validateBootWithdrawal(ctx); err != nil {
				return err
			}
		}
	}
	return nil
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
