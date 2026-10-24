package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const ctrlAltDelConfigPath = "/etc/systemd/system.conf.d/90-anquan-ctrl-alt-del.conf"

// Enforce continues to reconcile selected policies on the configured status
// interval. Optional cron audit watches are also reconciled in audit mode;
// Apply's policy gates still prevent enforcing any host hardening in that mode.
func (m *Manager) reconcileEnforcedPolicies(ctx context.Context) error {
	if !m.Config.Enabled || (m.Config.Policies.Mode != "enforce" && !m.hasCronAuditWatches()) {
		return nil
	}
	statuses, err := m.Apply(ctx)
	if m.ReconcileResult != nil {
		if recordErr := m.ReconcileResult(statuses, err); recordErr != nil {
			if err != nil && errors.Is(recordErr, err) {
				return recordErr
			}
			return errors.Join(err, recordErr)
		}
	}
	return err
}

func (m *Manager) readSysctl(ctx context.Context, key string) (string, error) {
	out, err := m.Runner.Run(ctx, "sysctl", "-n", key)
	value := normalizePolicyValue(out)
	if err == nil && value == "" {
		err = fmt.Errorf("sysctl %s returned no effective value", key)
	}
	return value, err
}

func (m *Manager) writeSysctl(ctx context.Context, key, value string) error {
	if _, err := m.Runner.Run(ctx, "sysctl", "-w", key+"="+value); err != nil {
		return err
	}
	actual, err := m.readSysctl(ctx, key)
	if err != nil {
		return err
	}
	if normalizePolicyValue(value) != actual {
		return fmt.Errorf("sysctl %s did not take effect: expected %q, actual %q", key, value, actual)
	}
	return nil
}

func (m *Manager) ctrlAltDelState(ctx context.Context) (string, error) {
	out, err := m.Runner.Run(ctx, "systemctl", "is-enabled", "ctrl-alt-del.target")
	state := strings.TrimSpace(out)
	// is-enabled exits nonzero for several valid states, including masked.
	switch state {
	case "masked", "masked-runtime", "enabled", "enabled-runtime", "disabled", "static", "indirect", "alias", "linked", "linked-runtime", "generated", "transient":
		return state, nil
	}
	if err == nil {
		err = fmt.Errorf("cannot determine ctrl-alt-del.target mask state: %q", state)
	}
	return state, err
}

func (m *Manager) ctrlAltDelBurstAction(ctx context.Context) (string, error) {
	out, err := m.Runner.Run(ctx, "systemctl", "show", "--property=CtrlAltDelBurstAction", "--value")
	action := strings.TrimSpace(out)
	if err == nil && action == "" {
		err = errors.New("systemd does not expose CtrlAltDelBurstAction; cannot verify burst reboot protection")
	}
	return action, err
}

func (m *Manager) setCtrlAltDelState(ctx context.Context, state string) error {
	if err := m.validateCtrlAltDelPaths(); err != nil {
		return err
	}
	args := []string{"unmask", "ctrl-alt-del.target"}
	if state == "masked" {
		args = []string{"mask", "ctrl-alt-del.target"}
	}
	if _, err := m.Runner.Run(ctx, "systemctl", args...); err != nil {
		return err
	}
	if state == "masked-runtime" {
		if _, err := m.Runner.Run(ctx, "systemctl", "mask", "--runtime", "ctrl-alt-del.target"); err != nil {
			return err
		}
	}
	actual, err := m.ctrlAltDelState(ctx)
	if err != nil {
		return err
	}
	wantMasked := state == "masked" || state == "masked-runtime"
	actualMasked := actual == "masked" || actual == "masked-runtime"
	if wantMasked != actualMasked || wantMasked && actual != state {
		return fmt.Errorf("ctrl-alt-del.target mask did not take effect: expected %s, actual %s", state, actual)
	}
	return nil
}

func (m *Manager) restoreRuntime(ctx context.Context, values map[string]string, cadState *string) error {
	var errs []error
	for _, key := range sortedKeys(values) {
		if err := m.writeSysctl(ctx, key, values[key]); err != nil {
			errs = append(errs, err)
		}
	}
	if cadState != nil {
		// Restore manager settings even when an earlier SSH/audit rollback failed
		// before activate reached the systemd manager reload step.
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reexec"); err != nil {
			errs = append(errs, err)
		}
		if err := m.setCtrlAltDelState(ctx, *cadState); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) validateCtrlAltDelPaths() error {
	for _, path := range []string{"/etc/systemd/system/ctrl-alt-del.target", "/run/systemd/system/ctrl-alt-del.target"} {
		full := m.path(path)
		info, err := os.Lstat(full)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(full)
			if err == nil && target == "/dev/null" {
				continue
			}
		}
		return fmt.Errorf("CtrlAltDel protection unsupported: %s has a custom unit or alias; refusing to replace or unmask it", path)
	}
	return nil
}

func (m *Manager) validateEffectivePolicies(ctx context.Context) error {
	for _, check := range m.checkPolicies(ctx) {
		if !check.Compliant {
			reason := check.Error
			if reason == "" {
				reason = check.Message
			}
			return fmt.Errorf("policy %s did not take effect: expected %q, actual %q: %s", check.Setting, check.Expected, check.Actual, reason)
		}
	}
	return nil
}

func sessionPolicyScript(seconds int) string {
	return fmt.Sprintf("# Managed by anquan; new interactive Bash sessions only.\ncase $- in\n  *i*) TMOUT=%d; readonly TMOUT; export TMOUT ;;\nesac\n", seconds)
}

func (m *Manager) checkSessionTimeout(ctx context.Context) PolicyCheck {
	want := strconv.Itoa(m.Config.Policies.SessionTimeoutSeconds)
	// Source the real global login profile in a fresh interactive Bash. Merely
	// finding a matching assignment in our file cannot prove it is loaded.
	probe := `HISTFILE=/dev/null; . "$1" >/dev/null; printf '\n__ANQUAN_TMOUT__%s\n' "${TMOUT-}"; declare -p TMOUT`
	out, err := m.Runner.Run(ctx, "bash", "--noprofile", "--norc", "-i", "-c", probe, "anquan-policy-check", m.path("/etc/profile"))
	actual := "unset"
	readonly, exported := false, false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "__ANQUAN_TMOUT__") {
			actual = strings.TrimPrefix(line, "__ANQUAN_TMOUT__")
		}
		if fields := strings.Fields(line); len(fields) >= 3 && fields[0] == "declare" && strings.HasPrefix(fields[2], "TMOUT=") {
			readonly = strings.Contains(fields[1], "r")
			exported = strings.Contains(fields[1], "x")
		}
	}
	c := policyValueCheck("session_timeout_seconds", want+" (readonly, exported)", actual, err)
	c.Compliant = err == nil && actual == want && readonly && exported
	if readonly && exported {
		c.Actual = actual + " (readonly, exported)"
	}
	c.Message = "Checked a fresh interactive Bash using /etc/profile; existing sessions require a new login. Other shells and running programs are outside TMOUT scope."
	return c
}

func (m *Manager) validateSessionPolicy(ctx context.Context) error {
	if m.Config.Policies.SessionTimeoutSeconds == 0 {
		return nil
	}
	if _, err := os.Stat(m.path("/etc/profile")); err != nil {
		return fmt.Errorf("session timeout requires a readable /etc/profile: %w", err)
	}
	c := m.checkSessionTimeout(ctx)
	if !c.Compliant {
		return fmt.Errorf("session timeout did not take effect: expected %s, actual %s: %s", c.Expected, c.Actual, c.Error)
	}
	return nil
}
