package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const sudoRestrictionPath = "/etc/sudoers.d/zzzz-anquan-restrict"

// A terminal negative command specification supersedes earlier direct and
// group grants. Keeping it in a separately owned file makes removing this
// policy restore the original rules without rewriting administrator files.
func (m *Manager) sudoRestrictionFile() string {
	var b strings.Builder
	b.WriteString("# Managed by anquan; terminal grant tags override earlier rules. Only restrict_users receive !ALL.\n")
	restricted := map[string]bool{}
	for _, user := range m.Config.Sudo.RestrictUsers {
		restricted[user] = true
	}
	for _, user := range m.sudoPolicyUsers() {
		// PASSWD does not override exempt_group. A user-scoped reset also
		// clears a compiled-in or earlier user/group-scoped exemption without
		// changing password policy for unrelated users.
		fmt.Fprintf(&b, "Defaults:%s !exempt_group\n", user)
		if restricted[user] {
			fmt.Fprintf(&b, "%s ALL=(ALL:ALL) !ALL\n", user)
		}
		for _, grant := range m.Config.Sudo.Grants {
			if grant.User != user {
				continue
			}
			runAs := grant.RunAs
			if runAs == "" {
				runAs = "root"
			}
			tag := "PASSWD:"
			if grant.NoPasswd {
				tag = "NOPASSWD:"
			}
			fmt.Fprintf(&b, "%s ALL=(%s) %s NOSETENV: %s\n", user, runAs, tag, strings.Join(grant.Commands, ", "))
		}
	}
	return b.String()
}

// We support the local files policy with a terminal includedir only. A rule
// parsed after ours, or an LDAP/SSSD policy source, could grant privileges again.
func (m *Manager) validateSudoRestrictionOrder() error {
	read := func(path string, optional bool) (string, error) {
		if err := noSymlink(m.path(path)); err != nil {
			return "", err
		}
		b, err := os.ReadFile(m.path(path))
		if optional && os.IsNotExist(err) {
			return "", nil
		}
		return string(b), err
	}
	nss, err := read("/etc/nsswitch.conf", true)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(nss, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "sudoers" && strings.TrimSpace(value) != "files" {
			return errors.New("sudo restriction unsupported: sudoers NSS sources must be local files only")
		}
	}
	plugins, err := read("/etc/sudo.conf", true)
	if err != nil {
		return err
	}
	plugins = strings.ReplaceAll(strings.ReplaceAll(plugins, "\\\r\n", ""), "\\\n", "")
	for _, line := range strings.Split(plugins, "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) >= 3 && strings.EqualFold(fields[0], "Plugin") &&
			(fields[1] != "sudoers_policy" && fields[1] != "sudoers_io" && fields[1] != "sudoers_audit" || filepath.Base(fields[2]) != "sudoers.so") {
			return errors.New("sudo restriction unsupported: only the standard sudoers plugins are supported")
		}
		if len(fields) > 3 && strings.EqualFold(fields[0], "Plugin") {
			// Since sudo 1.9.1 the audit plugin parses sudoers, so checking
			// arguments only on sudoers_policy would miss sudoers_file there.
			return errors.New("sudo restriction unsupported: sudoers plugin arguments may select an alternate policy source")
		}
	}
	main, err := read("/etc/sudoers", false)
	if err != nil {
		return fmt.Errorf("read main sudoers for restriction ordering: %w", err)
	}
	last := ""
	for _, line := range strings.Split(main, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#include")) {
			continue
		}
		last = strings.TrimSpace(strings.SplitN(line, " #", 2)[0])
	}
	if last != "@includedir /etc/sudoers.d" && last != "#includedir /etc/sudoers.d" {
		return errors.New("sudo restriction unsupported: /etc/sudoers must end with includedir /etc/sudoers.d so no later rule can restore broad grants")
	}
	entries, err := os.ReadDir(m.path("/etc/sudoers.d"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	ours := filepath.Base(sudoRestrictionPath)
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue // sudoers includedir skips these names.
		}
		if name > ours {
			return fmt.Errorf("sudo restriction unsupported: %s is parsed after the terminal Agent policy", name)
		}
	}
	return nil
}

func (m *Manager) validateSudoRestrictions(ctx context.Context) error {
	if len(m.sudoPolicyUsers()) == 0 {
		return nil
	}
	if err := m.validateSudoGrantAuthentication(); err != nil {
		return err
	}
	if _, err := m.Runner.LookPath("sudo"); err != nil {
		return fmt.Errorf("cannot verify sudo restriction: %w", err)
	}
	if err := m.validateSudoRestrictedAccounts(ctx); err != nil {
		return err
	}
	if err := m.validateSudoRestrictionOrder(); err != nil {
		return err
	}
	if err := noSymlink(m.path(sudoRestrictionPath)); err != nil {
		return err
	}
	actual, err := os.ReadFile(m.path(sudoRestrictionPath))
	if err != nil {
		return err
	}
	if string(actual) != m.sudoRestrictionFile() {
		return errors.New("terminal sudo restriction differs from the configured users and grants")
	}
	restricted := map[string]bool{}
	for _, user := range m.Config.Sudo.RestrictUsers {
		restricted[user] = true
	}
	for _, user := range m.sudoPolicyUsers() {
		if err := m.validateSudoExemptions(ctx, user, m.sudoUserRequiresAuthentication(user)); err != nil {
			return err
		}
		for _, grant := range m.Config.Sudo.Grants {
			if grant.User != user {
				continue
			}
			runAs := grant.RunAs
			if runAs == "" {
				runAs = "root"
			}
			for _, command := range grant.Commands {
				args := append([]string{"-n", "-l", "-U", user, "-u", runAs, "--"}, strings.Fields(command)...)
				if _, err := m.Runner.Run(ctx, "sudo", args...); err != nil {
					return fmt.Errorf("sudo restriction did not retain grant for %s: %w", user, err)
				}
			}
		}
		if !restricted[user] {
			continue // Additive grants keep other administrator permissions.
		}
		probe := ""
		for _, name := range []string{"sh", "su", "env", "true", "false", "cat", "ls", "id"} {
			path, err := m.Runner.LookPath(name)
			if err != nil {
				continue
			}
			if !m.sudoCommandIsGranted(user, path) {
				probe = path
				break
			}
		}
		if probe == "" {
			return errors.New("cannot verify sudo restriction: no installed command outside the configured grants is available")
		}
		out, err := m.Runner.Run(ctx, "sudo", "-n", "-l", "-U", user, "-u", "root", "--", probe)
		if err == nil {
			return fmt.Errorf("sudo restriction ineffective: %s can still run ungranted %s as root", user, probe)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		denial := strings.ToLower(out + " " + err.Error())
		if !strings.Contains(denial, "not allowed") && !strings.Contains(denial, "not permitted") && !strings.Contains(denial, "may not run sudo") && !strings.Contains(denial, "not in the sudoers") {
			return fmt.Errorf("cannot verify sudo denial for %s: %w", user, err)
		}
	}
	return nil
}

func (m *Manager) sudoCommandIsGranted(user, path string) bool {
	actual, _ := os.Stat(m.path(path))
	for _, grant := range m.Config.Sudo.Grants {
		if grant.User != user {
			continue
		}
		for _, command := range grant.Commands {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				continue
			}
			if fields[0] == path {
				return true
			}
			// sudo identifies a command by its filesystem identity as well as
			// its path. A /bin -> /usr/bin alias must not be used as a supposed
			// ungranted denial probe for an explicitly allowed command.
			if other, err := os.Stat(m.path(fields[0])); err == nil && actual != nil && os.SameFile(actual, other) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) checkSudoRestrictions(ctx context.Context) []PolicyCheck {
	if !m.Config.Sudo.Enabled || len(m.sudoPolicyUsers()) == 0 {
		return nil
	}
	err := m.validateSudoRestrictions(ctx)
	users := append([]string(nil), m.Config.Sudo.RestrictUsers...)
	sort.Strings(users)
	check := PolicyCheck{Setting: "sudo.restrict_users", Expected: strings.Join(users, ", ") + " restricted to configured grants and authentication tags", Compliant: err == nil}
	check.Message = "PASSWD/NOPASSWD policy is checked. Sudo credential caching, same-identity execution and the host authentication stack still govern when a prompt occurs."
	if len(users) == 0 {
		check.Setting = "sudo.grants"
		check.Expected = "configured command grants and authentication tags"
		check.Message = "Additive grants retain other administrator permissions. " + check.Message
	}
	if err == nil {
		check.Actual = check.Expected
	} else {
		check.Actual = "restriction not verified"
		check.Error = err.Error()
	}
	return []PolicyCheck{check}
}

func (m *Manager) sudoPolicyUsers() []string {
	users := map[string]bool{}
	for _, user := range m.Config.Sudo.RestrictUsers {
		users[user] = true
	}
	for _, grant := range m.Config.Sudo.Grants {
		users[grant.User] = true
	}
	return sortedKeys(users)
}

func (m *Manager) validateSudoGrantAuthentication() error {
	seen := map[string]bool{}
	for _, grant := range m.Config.Sudo.Grants {
		runAs := grant.RunAs
		if runAs == "" {
			runAs = "root"
		}
		for _, command := range grant.Commands {
			key := grant.User + "\x00" + runAs + "\x00" + strings.Join(strings.Fields(command), " ")
			if previous, ok := seen[key]; ok && previous != grant.NoPasswd {
				return fmt.Errorf("conflicting sudo PASSWD/NOPASSWD grants for %s as %s: %s", grant.User, runAs, command)
			}
			seen[key] = grant.NoPasswd
		}
	}
	return nil
}

func (m *Manager) sudoUserRequiresAuthentication(user string) bool {
	for _, grant := range m.Config.Sudo.Grants {
		if grant.User == user && !grant.NoPasswd {
			return true
		}
	}
	return false
}

var sudoExemptAssignment = regexp.MustCompile(`(?:^|[\s,])exempt_group\s*=`)
var sudoExemptReset = regexp.MustCompile(`(?:^|[\s,])!exempt_group(?:$|[\s,])`)

// sudo -ll is read-only: its matching Defaults include our user-scoped reset,
// and its separate bound-Defaults section includes ALL command/runas Defaults.
// Those later stages can reinstate exempt_group. Conservatively reject any such
// assignment instead of treating PASSWD as proof that authentication occurs.
// See sudo-project/sudo plugins/sudoers/check.c (user_is_exempt), defaults.c
// (per-command defaults), and lookup.c (explicit tags override authenticate).
func (m *Manager) validateSudoExemptions(ctx context.Context, user string, requireAuthentication bool) error {
	out, err := m.Runner.Run(ctx, "sudo", "-n", "-ll", "-U", user)
	if err != nil {
		return fmt.Errorf("cannot inspect sudo authentication exemptions for %s: %w", user, err)
	}
	matching := "Matching Defaults entries for " + user + " on "
	bound := "Runas and Command-specific defaults for " + user + ":"
	privileges := "User " + user + " may run the following commands on "
	start := strings.Index(out, matching)
	privilegeAt := strings.Index(out, privileges)
	if start < 0 || privilegeAt <= start {
		return fmt.Errorf("cannot verify sudo authentication for %s: complete English long-list Defaults output is required", user)
	}
	defaultsEnd := privilegeAt
	boundAt := strings.Index(out, bound)
	if boundAt >= 0 {
		if boundAt <= start || boundAt >= privilegeAt {
			return fmt.Errorf("cannot verify sudo authentication for %s: malformed bound-Defaults output", user)
		}
		defaultsEnd = boundAt
		if requireAuthentication && sudoExemptAssignment.MatchString(out[boundAt:privilegeAt]) {
			return fmt.Errorf("sudo PASSWD policy unsupported for %s: command/runas-specific exempt_group can bypass authentication; remove that exemption before enforcing the grant", user)
		}
	}
	if !sudoExemptReset.MatchString(out[start:defaultsEnd]) {
		return fmt.Errorf("sudo authentication exemption reset did not take effect for %s", user)
	}
	return nil
}

func (m *Manager) validateSudoRestrictedAccounts(ctx context.Context) error {
	for _, user := range m.Config.Sudo.RestrictUsers {
		uid, err := m.Runner.Run(ctx, "id", "-u", user)
		if err != nil {
			return fmt.Errorf("sudo restriction account %s is unavailable: %w", user, err)
		}
		n, err := strconv.ParseUint(strings.TrimSpace(uid), 10, 32)
		if err != nil {
			return fmt.Errorf("sudo restriction account %s has an unverifiable UID", user)
		}
		if n == 0 {
			return fmt.Errorf("sudo restriction cannot limit UID 0 account %s", user)
		}
	}
	return nil
}
