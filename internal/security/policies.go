package security

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type PolicyCheck struct {
	Setting   string `json:"setting"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Compliant bool   `json:"compliant"`
	Message   string `json:"message,omitempty"`
}

func (m *Manager) checkPolicies(ctx context.Context) []PolicyCheck {
	if !m.Config.Enabled {
		return nil
	}
	p := m.Config.Policies
	checks := []PolicyCheck{}
	add := func(key, want, actual string, err error) {
		v := PolicyCheck{Setting: key, Expected: want, Actual: actual, Compliant: err == nil && strings.TrimSpace(want) == strings.TrimSpace(actual)}
		if err != nil {
			v.Message = err.Error()
		}
		checks = append(checks, v)
	}
	if p.SSH.Enabled {
		out, err := m.Runner.Run(ctx, "sshd", "-T")
		effective := parseSettings(out)
		if p.SSH.PasswordAuthentication != "" {
			add("ssh.password_authentication", p.SSH.PasswordAuthentication, effective["passwordauthentication"], err)
		}
		if p.SSH.PasswordAuthentication == "no" {
			add("ssh.kbd_interactive_authentication", "no", effective["kbdinteractiveauthentication"], err)
		}
		if p.SSH.PermitRootLogin != "" {
			add("ssh.permit_root_login", p.SSH.PermitRootLogin, effective["permitrootlogin"], err)
		}
		if len(p.SSH.AllowUsers) > 0 {
			add("ssh.allow_users", strings.Join(p.SSH.AllowUsers, " "), effective["allowusers"], err)
		}
		if len(p.SSH.AllowSources) > 0 {
			out, err = m.Runner.Run(ctx, "nft", "list", "table", "inet", "anquan_ssh")
			actual := "absent"
			if err == nil && strings.Contains(out, "restrict_ssh") {
				actual = "managed restriction present"
			}
			add("ssh.allow_sources", "managed restriction present", actual, err)
		}
	}
	for _, k := range sortedKeys(p.Sysctl) {
		out, err := m.Runner.Run(ctx, "sysctl", "-n", k)
		add("sysctl."+k, p.Sysctl[k], strings.TrimSpace(out), err)
	}
	for _, grant := range m.Config.Sudo.Grants {
		out, err := m.Runner.Run(ctx, "sudo", "-n", "-l", "-U", grant.User)
		compliant := err == nil
		for _, cmd := range grant.Commands {
			if !strings.Contains(out, cmd) {
				compliant = false
			}
		}
		message := "existing broad grants may still permit wider access; this check does not revoke other sudoers rules"
		if err != nil {
			message = err.Error() + "; " + message
		}
		checks = append(checks, PolicyCheck{Setting: "sudo.grant." + grant.User, Expected: strings.Join(grant.Commands, ", "), Actual: strings.TrimSpace(out), Compliant: compliant, Message: message})
	}
	if p.SessionTimeoutSeconds > 0 {
		raw, err := os.ReadFile(m.path(sessionConfigPath))
		want := fmt.Sprintf("TMOUT=%d", p.SessionTimeoutSeconds)
		actual := "absent"
		if strings.Contains(string(raw), want) {
			actual = want
		}
		add("session_timeout_seconds", want, actual, err)
	}
	if p.DisableCtrlAltDel {
		out, err := m.Runner.Run(ctx, "systemctl", "is-enabled", "ctrl-alt-del.target")
		if strings.TrimSpace(out) == "masked" {
			err = nil
		}
		add("disable_ctrl_alt_del", "masked", strings.TrimSpace(out), err)
	}
	if p.GRUB.Enabled {
		raw, err := os.ReadFile(m.path(grubConfigPath))
		actual := "absent"
		if strings.Contains(string(raw), "password_pbkdf2 anquan-admin grub.pbkdf2.sha512.") {
			actual = "configured"
		}
		add("grub.password", "configured", actual, err)
	}
	return checks
}
