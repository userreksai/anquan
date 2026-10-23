package security

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type PolicyCheck struct {
	Setting   string `json:"setting"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Compliant bool   `json:"compliant"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

func policyValueCheck(setting, expected, actual string, err error) PolicyCheck {
	c := PolicyCheck{Setting: setting, Expected: expected, Actual: actual, Compliant: err == nil && normalizePolicyValue(expected) == normalizePolicyValue(actual)}
	if err != nil {
		c.Error = err.Error()
		c.Message = err.Error()
	}
	return c
}

func normalizePolicyValue(value string) string { return strings.Join(strings.Fields(value), " ") }

func (m *Manager) checkPolicies(ctx context.Context) []PolicyCheck {
	if !m.Config.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p := m.Config.Policies
	checks := []PolicyCheck{}
	if p.SSH.Enabled {
		checks = append(checks, m.checkSSHPolicy(ctx)...)
	}
	for _, key := range sortedKeys(p.Sysctl) {
		value, err := m.readSysctl(ctx, key)
		checks = append(checks, policyValueCheck("sysctl."+key, p.Sysctl[key], value, err))
	}
	if m.Config.Sudo.Enabled {
		checks = append(checks, m.checkSudoRestrictions(ctx)...)
		restricted := map[string]bool{}
		for _, user := range m.Config.Sudo.RestrictUsers {
			restricted[user] = true
		}
		for _, grant := range m.Config.Sudo.Grants {
			if restricted[grant.User] {
				continue
			} // fully verified by the terminal restriction above
			runAs := grant.RunAs
			if runAs == "" {
				runAs = "root"
			}
			for _, command := range grant.Commands {
				args := append([]string{"-n", "-l", "-U", grant.User, "-u", runAs, "--"}, strings.Fields(command)...)
				_, err := m.Runner.Run(ctx, "sudo", args...)
				actual := "allowed"
				if err != nil {
					actual = "not verified"
				}
				c := policyValueCheck("sudo.grant."+grant.User+"."+command, "allowed", actual, err)
				c.Message = "Additive grant only; use restrict_users to replace a user's broader sudo permissions."
				checks = append(checks, c)
			}
		}
	}
	if p.SessionTimeoutSeconds > 0 {
		checks = append(checks, m.checkSessionTimeout(ctx))
	}
	if p.DisableCtrlAltDel {
		state, err := m.ctrlAltDelState(ctx)
		c := policyValueCheck("disable_ctrl_alt_del", "masked", state, err)
		c.Compliant = err == nil && (state == "masked" || state == "masked-runtime")
		checks = append(checks, c)
		burst, burstErr := m.ctrlAltDelBurstAction(ctx)
		checks = append(checks, policyValueCheck("ctrl_alt_del_burst_action", "none", burst, burstErr))
	}
	if p.GRUB.Enabled {
		checks = append(checks, m.checkBootPolicy(ctx)...)
	}
	return checks
}

func policyStatus(mode string, checks []PolicyCheck) (string, string) {
	if len(checks) == 0 {
		return "no_policies", "No host hardening policies selected."
	}
	failed, errors := 0, 0
	for _, check := range checks {
		if !check.Compliant {
			failed++
		}
		if check.Error != "" {
			errors++
		}
	}
	if errors > 0 {
		return "error", fmt.Sprintf("Could not inspect %d of %d requested policies; see individual check errors.", errors, len(checks))
	}
	if failed > 0 {
		if mode == "audit" {
			return "audit_drift", fmt.Sprintf("Audit only: %d of %d requested policies differ; no hardening was applied.", failed, len(checks))
		}
		return "drift", fmt.Sprintf("%d of %d requested policies differ from effective host settings; see target and actual values.", failed, len(checks))
	}
	if mode == "audit" {
		return "audit", fmt.Sprintf("Audit only: all %d requested policies match effective host settings.", len(checks))
	}
	return "compliant", fmt.Sprintf("All %d requested policies match effective host settings.", len(checks))
}
