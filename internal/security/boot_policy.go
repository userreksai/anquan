package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const bootRecoveryConfigPath = "/etc/default/grub.d/zzzz-anquan-single-user.cfg"
const bootGeneratedConfigPath = "/boot/grub/grub.cfg"

type bootRollbackContextKey struct{}

func withBootRollback(ctx context.Context) context.Context {
	return context.WithValue(ctx, bootRollbackContextKey{}, true)
}

func isBootRollback(ctx context.Context) bool {
	rollback, _ := ctx.Value(bootRollbackContextKey{}).(bool)
	return rollback
}

// Before generated-file snapshots existed, the journal recorded only GRUB
// generator snippets. Regenerate those restored snippets for a legacy recovery
// instead of leaving a generated menu from the interrupted transaction active.
func (m *Manager) bootRecoveryContext(ctx context.Context, interrupted transactionJournal) (context.Context, error) {
	for _, before := range interrupted.Before {
		if before.Path == bootGeneratedConfigPath {
			return withBootRollback(ctx), nil
		}
	}
	a, b := interrupted.Previous.configuredFiles(), interrupted.Next.configuredFiles()
	changed := false
	for _, p := range []string{grubConfigPath, bootRecoveryConfigPath} {
		changed = changed || a[p] != b[p] || interrupted.Dirty[p]
	}
	if changed {
		if err := m.updateGRUB(ctx); err != nil {
			return nil, fmt.Errorf("recover legacy GRUB generation: %w", err)
		}
		// The restored snippets represent the OLD policy. The current config
		// may contain a different hash, so only verify the regenerated syntax.
		if _, err := m.readGeneratedBootConfig(ctx); err != nil {
			return nil, fmt.Errorf("validate recovered legacy GRUB generation: %w", err)
		}
	}
	return withBootRollback(ctx), nil
}

func bootAuthenticationScript(hash string) string {
	return "#!/bin/sh\n# Managed by anquan. GRUB authentication protects editing and restricted boot entries.\ncat <<'ANQUAN_GRUB_AUTH'\nset superusers=\"anquan-admin\"\nexport superusers\npassword_pbkdf2 anquan-admin " + hash + "\nANQUAN_GRUB_AUTH\n"
}

// Deliberately limit automation to a known generator and target. Choosing an
// arbitrary grub2-mkconfig target may leave the actual firmware entry unchanged.
func (m *Manager) validateBootEnvironment() error {
	for _, command := range []string{"update-grub", "grub-script-check"} {
		if _, err := m.Runner.LookPath(command); err != nil {
			return fmt.Errorf("GRUB enforcement unsupported: %s is required: %w", command, err)
		}
	}
	for _, path := range []string{"/boot/grub", "/etc/grub.d"} {
		if err := noSymlink(m.path(path)); err != nil {
			return err
		}
		info, err := os.Stat(m.path(path))
		if err != nil || !info.IsDir() {
			return fmt.Errorf("GRUB enforcement unsupported: %s must be a directory", path)
		}
	}
	for _, path := range []string{"/etc/default/grub", bootGeneratedConfigPath} {
		if err := noSymlink(m.path(path)); err != nil {
			return err
		}
		info, err := os.Stat(m.path(path))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("GRUB enforcement unsupported: %s must be an existing regular file", path)
		}
	}
	return nil
}

func (m *Manager) snapshotBootFiles(tx *transaction, previous, next manifest) error {
	a, b := previous.configuredFiles(), next.configuredFiles()
	changed := false
	for _, p := range []string{grubConfigPath, bootRecoveryConfigPath} {
		if a[p] != b[p] || tx.dirty[p] {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	for _, p := range []string{bootGeneratedConfigPath, bootGeneratedConfigPath + ".new"} {
		if err := tx.capture(p); err != nil {
			return err
		}
	}
	return nil
}

// GRUB scripts contain shell-like quoting and nested blocks. Tokenizing rather
// than looking for a recovery title prevents a comment, a quoted brace, or an
// unrestricted entry with a different title from producing a false success.
func bootTokens(raw string) ([]string, error) {
	var tokens []string
	var word strings.Builder
	quote := byte(0)
	variableBraces := 0
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(raw) {
				i++
				word.WriteByte(raw[i])
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' && i+1 < len(raw) {
			i++
			if raw[i] != '\n' {
				word.WriteByte(raw[i])
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '#' && word.Len() == 0 {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			flush()
			tokens = append(tokens, "\n")
			continue
		}
		if c == '{' && i > 0 && raw[i-1] == '$' {
			variableBraces++
			word.WriteByte(c)
			continue
		}
		if c == '}' && variableBraces > 0 {
			variableBraces--
			word.WriteByte(c)
			continue
		}
		switch c {
		case ' ', '\t', '\r':
			flush()
		case '\n', ';', '{', '}':
			flush()
			tokens = append(tokens, string(c))
		default:
			word.WriteByte(c)
		}
	}
	if quote != 0 || variableBraces != 0 {
		return nil, errors.New("unsupported unterminated GRUB quoting or parameter expansion")
	}
	flush()
	return tokens, nil
}

var bootRecoveryTitle = regexp.MustCompile(`(?i)(recovery|single[ -]?user|rescue|emergency)`)

func bootCommandIsRecovery(words []string) bool {
	for _, word := range words {
		v := strings.ToLower(word)
		if v == "single" || v == "1" || v == "s" || v == "-s" || v == "rescue" || v == "emergency" || strings.HasPrefix(v, "init=") || strings.HasPrefix(v, "rdinit=") || strings.HasPrefix(v, "systemd.unit=rescue") || strings.HasPrefix(v, "systemd.unit=emergency") || strings.HasPrefix(v, "rd.systemd.unit=rescue") || strings.HasPrefix(v, "rd.systemd.unit=emergency") || strings.HasPrefix(v, "rd.break") || v == "rd.shell" || strings.HasPrefix(v, "rd.shell=1") || strings.HasPrefix(v, "systemd.debug_shell") || strings.HasPrefix(v, "rd.systemd.debug_shell") || strings.HasPrefix(v, "systemd.run=") || strings.HasPrefix(v, "rd.systemd.run=") {
			return true
		}
	}
	return false
}

func (m *Manager) validateBootText(raw string, protectSingleUser bool) error {
	tokens, err := bootTokens(raw)
	if err != nil {
		return err
	}
	password := m.Config.Policies.GRUB.PasswordHash
	superusers, exported, passwordFound, menuCount, recoveryCount := false, false, false, 0, 0
	for i := 0; i < len(tokens); i++ {
		word := tokens[i]
		switch word {
		case "set":
			if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "superusers=") {
				if tokens[i+1] != "superusers=anquan-admin" || superusers {
					return errors.New("generated GRUB configuration overrides or duplicates the required superusers policy")
				}
				superusers = true
			}
			if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "menuentry_id_option=") && tokens[i+1] != "menuentry_id_option=--id" && tokens[i+1] != "menuentry_id_option=" {
				return errors.New("GRUB protection unsupported: menuentry ID variable contains privilege options")
			}
		case "unset":
			if i+1 < len(tokens) && tokens[i+1] == "superusers" {
				return errors.New("generated GRUB configuration removes the required superusers policy")
			}
		case "export":
			if i+1 < len(tokens) && tokens[i+1] == "superusers" {
				exported = true
			}
		case "password", "password_pbkdf2":
			if i+2 < len(tokens) && tokens[i+1] == "anquan-admin" {
				if word != "password_pbkdf2" || passwordFound || !validGRUBPasswordHash(tokens[i+2]) || (password != "" && tokens[i+2] != password) {
					return errors.New("generated GRUB authentication does not match the requested PBKDF2 credential")
				}
				passwordFound = true
			}
		case "eval", "configfile":
			return fmt.Errorf("GRUB protection unsupported: dynamic %s directives cannot be verified", word)
		case "load_env":
			if superusers {
				return errors.New("GRUB protection unsupported: loading environment after authentication may replace its policy")
			}
		case "source":
			if i+1 >= len(tokens) {
				return errors.New("GRUB protection unsupported: incomplete source directive")
			}
			// Debian's standard 41_custom loads custom.cfg only if present. An
			// absent file is safe; other sources require explicit integration.
			source := tokens[i+1]
			if source != "${config_directory}/custom.cfg" && source != "$prefix/custom.cfg" {
				return errors.New("GRUB protection unsupported: externally sourced configuration cannot be verified")
			}
			if _, err := os.Lstat(m.path("/boot/grub/custom.cfg")); !os.IsNotExist(err) {
				return errors.New("GRUB protection unsupported: custom.cfg may override authentication")
			}
		case "menuentry":
			if !superusers || !exported || !passwordFound {
				return errors.New("GRUB menu appears before its authentication policy")
			}
			start := i + 1
			open := start
			for open < len(tokens) && tokens[open] != "{" && tokens[open] != "\n" {
				open++
			}
			if open >= len(tokens) || tokens[open] != "{" || start == open {
				return errors.New("GRUB protection unsupported: dynamic or multiline menuentry header")
			}
			end, depth := open+1, 1
			for ; end < len(tokens) && depth > 0; end++ {
				if tokens[end] == "{" {
					depth++
				} else if tokens[end] == "}" {
					depth--
				}
			}
			if depth != 0 {
				return errors.New("generated GRUB menuentry has an unclosed block")
			}
			menuCount++
			header, body := tokens[start:open], tokens[open+1:end-1]
			recovery := bootRecoveryTitle.MatchString(header[0])
			for j := 0; j < len(body); j++ {
				if body[j] != "linux" && body[j] != "linuxefi" && body[j] != "linux16" {
					continue
				}
				k := j + 1
				for k < len(body) && body[k] != "\n" && body[k] != ";" {
					k++
				}
				recovery = recovery || bootCommandIsRecovery(body[j+1:k])
			}
			if recovery {
				recoveryCount++
				if protectSingleUser {
					for _, option := range header {
						if option == "--unrestricted" || strings.HasPrefix(option, "$") || strings.HasPrefix(option, "--users") {
							// The generated $menuentry_id_option only provides
							// an ID; reject any other dynamic privilege option.
							if option == "$menuentry_id_option" {
								continue
							}
							return errors.New("single-user or recovery GRUB entry permits unauthenticated or unverifiable access")
						}
					}
				}
			}
		}
	}
	if !superusers || !exported || !passwordFound || menuCount == 0 {
		return errors.New("generated GRUB configuration lacks verifiable authentication and boot entries")
	}
	if protectSingleUser && recoveryCount == 0 {
		return errors.New("single-user protection cannot be verified: no generated recovery entry was found")
	}
	return nil
}

func (m *Manager) readGeneratedBootConfig(ctx context.Context) ([]byte, error) {
	if err := m.validateBootEnvironment(); err != nil {
		return nil, err
	}
	if _, err := m.Runner.Run(ctx, "grub-script-check", m.path(bootGeneratedConfigPath)); err != nil {
		return nil, fmt.Errorf("generated GRUB syntax validation failed: %w", err)
	}
	raw, err := os.ReadFile(m.path(bootGeneratedConfigPath))
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, errors.New("generated GRUB configuration is too large to verify")
	}
	return raw, nil
}

func (m *Manager) validateGeneratedBootFiles(ctx context.Context, protectSingleUser bool) error {
	raw, err := m.readGeneratedBootConfig(ctx)
	if err != nil {
		return err
	}
	return m.validateBootText(string(raw), protectSingleUser)
}

func (m *Manager) validateBootWithdrawal(ctx context.Context) error {
	raw, err := m.readGeneratedBootConfig(ctx)
	if err != nil {
		return err
	}
	tokens, err := bootTokens(string(raw))
	if err != nil {
		return err
	}
	for i, token := range tokens {
		if (token == "password" || token == "password_pbkdf2") && i+1 < len(tokens) && tokens[i+1] == "anquan-admin" {
			return errors.New("GRUB withdrawal did not remove Agent boot authentication from the generated configuration; external generator rules may still define it")
		}
	}
	return nil
}

func (m *Manager) validateBootPolicy(ctx context.Context) error {
	if !m.Config.Policies.GRUB.Enabled {
		return nil
	}
	return m.validateGeneratedBootFiles(ctx, m.Config.Policies.GRUB.ProtectSingleUser)
}

func (m *Manager) checkBootPolicy(ctx context.Context) []PolicyCheck {
	if !m.Config.Policies.GRUB.Enabled {
		return nil
	}
	check := PolicyCheck{Setting: "grub.authentication", Expected: "GRUB editing and console require authentication"}
	if m.Config.Policies.GRUB.ProtectSingleUser {
		check.Setting = "grub.single_user"
		check.Expected += "; generated recovery entries require authentication"
	}
	if err := m.validateBootPolicy(ctx); err != nil {
		check.Actual = "boot protection not verified"
		check.Error = err.Error()
	} else {
		check.Compliant = true
		check.Actual = check.Expected
	}
	return []PolicyCheck{check}
}
