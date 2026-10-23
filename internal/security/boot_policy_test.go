package security

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const testBootHash = "grub.pbkdf2.sha512.10000.ABCD.EFAB"

func testBootConfig() string {
	return "set superusers=\"anquan-admin\"\nexport superusers\npassword_pbkdf2 anquan-admin " + testBootHash + "\n" +
		"menuentry 'Linux' --unrestricted $menuentry_id_option 'linux-normal' {\n linux /vmlinuz root=/dev/sda1 ro quiet $vt_handoff\n}\n" +
		"submenu 'Advanced Linux' {\n menuentry 'Linux (recovery mode)' $menuentry_id_option 'linux-recovery' {\n linux /vmlinuz root=/dev/sda1 ro single\n }\n}\n"
}

func bootPolicyFixture(t *testing.T) *Manager {
	t.Helper()
	m, _ := testManager(t, Config{Enabled: true, Policies: PolicyConfig{Mode: "enforce", GRUB: GRUBConfig{Enabled: true, PasswordHash: testBootHash, ProtectSingleUser: true}}})
	put(t, m, "/etc/default/grub", []byte("GRUB_TIMEOUT=5\n"))
	put(t, m, "/etc/grub.d/00_header", []byte("#!/bin/sh\n"))
	put(t, m, bootGeneratedConfigPath, []byte(testBootConfig()))
	return m
}

func TestBootPolicyVerifiesGeneratedRecoveryAndNormalBoot(t *testing.T) {
	m := bootPolicyFixture(t)
	if err := m.validateBootPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	checks := m.checkBootPolicy(context.Background())
	if len(checks) != 1 || !checks[0].Compliant || strings.Contains(checks[0].Actual, testBootHash) {
		t.Fatalf("boot authentication status incorrect or exposed credential: %+v", checks)
	}
}

func TestBootPolicyRejectsGeneratedAuthenticationBypasses(t *testing.T) {
	base := testBootConfig()
	for name, raw := range map[string]string{
		"unrestricted-recovery":     strings.Replace(base, "'Linux (recovery mode)'", "'Linux (recovery mode)' --unrestricted", 1),
		"single-with-normal-title":  strings.Replace(strings.Replace(base, "'Linux (recovery mode)'", "'Unlabelled kernel' --unrestricted", 1), " ro single", " ro init=/bin/sh", 1),
		"wrong-hash":                strings.Replace(base, testBootHash, "grub.pbkdf2.sha512.10000.AAAA.BBBB", 1),
		"later-auth-reset":          base + "\nunset superusers\n",
		"later-password-reset":      base + "\npassword anquan-admin plaintext\n",
		"auth-after-menu":           "menuentry 'Unauthenticated' --unrestricted { linux /vmlinuz single; }\n" + base,
		"dynamic-config":            base + "\nconfigfile /other/grub.cfg\n",
		"dynamic-id-privilege":      "set menuentry_id_option=--unrestricted\n" + base,
		"late-environment-override": base + "\nload_env\n",
		"no-recovery":               strings.Replace(strings.Replace(base, "'Linux (recovery mode)'", "'Normal alternative'", 1), " ro single", " ro quiet", 1),
		"comment-only":              "# set superusers=anquan-admin\n# password_pbkdf2 anquan-admin " + testBootHash + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := bootPolicyFixture(t)
			put(t, m, bootGeneratedConfigPath, []byte(raw))
			if err := m.validateBootPolicy(context.Background()); err == nil {
				t.Fatal("authentication bypass or missing recovery verification accepted")
			}
		})
	}
}

func TestBootPolicyRejectsExternalCustomConfiguration(t *testing.T) {
	m := bootPolicyFixture(t)
	put(t, m, bootGeneratedConfigPath, []byte(testBootConfig()+"\nif [ -f ${config_directory}/custom.cfg ]; then\nsource ${config_directory}/custom.cfg\nfi\n"))
	if err := m.validateBootPolicy(context.Background()); err != nil {
		t.Fatalf("stock conditional source for absent custom.cfg rejected: %v", err)
	}
	put(t, m, "/boot/grub/custom.cfg", []byte("set superusers=\"\"\n"))
	if err := m.validateBootPolicy(context.Background()); err == nil {
		t.Fatal("external custom configuration accepted")
	}
}

func TestBootSnapshotsPreserveGeneratedFilesWithoutWriting(t *testing.T) {
	m := bootPolicyFixture(t)
	put(t, m, bootGeneratedConfigPath+".new", []byte("administrator staging contents"))
	before, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
	beforeNew, _ := os.ReadFile(m.path(bootGeneratedConfigPath + ".new"))
	tx := &transaction{manager: m, dirty: map[string]bool{}}
	previous := manifest{}
	next := manifest{Files: map[string]string{grubConfigPath: "new-authentication"}}
	if err := m.snapshotBootFiles(tx, previous, next); err != nil {
		t.Fatal(err)
	}
	if len(tx.before) != 2 {
		t.Fatalf("expected only the two generated preimages, got %+v", tx.before)
	}
	after, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
	if !bytes.Equal(before, after) {
		t.Fatal("snapshot changed generated config")
	}
	put(t, m, bootGeneratedConfigPath, []byte("partially generated config"))
	put(t, m, bootGeneratedConfigPath+".new", []byte("partially generated staging"))
	if err := m.restore(tx.before); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(m.path(bootGeneratedConfigPath))
	afterNew, _ := os.ReadFile(m.path(bootGeneratedConfigPath + ".new"))
	if !bytes.Equal(before, after) || !bytes.Equal(beforeNew, afterNew) {
		t.Fatal("generated or pre-existing staging config did not roll back exactly")
	}
}

func TestBootSnapshotRejectsNonRegularGeneratedTarget(t *testing.T) {
	m := bootPolicyFixture(t)
	if err := os.Mkdir(m.path(bootGeneratedConfigPath+".new"), 0700); err != nil {
		t.Fatal(err)
	}
	tx := &transaction{manager: m, dirty: map[string]bool{}}
	if err := m.snapshotBootFiles(tx, manifest{}, manifest{Files: map[string]string{grubConfigPath: "next"}}); err == nil {
		t.Fatal("non-regular staging target was accepted")
	}
}

type bootPolicyRunner struct {
	*fakeRunner
	manager           *Manager
	updates           int
	bad               bool
	partial           bool
	staleWithdrawal   bool
	generatedOverride string
}

func (r *bootPolicyRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "update-grub" {
		r.updates++
		text := strings.ReplaceAll(testBootConfig(), testBootHash, r.manager.Config.Policies.GRUB.PasswordHash)
		if _, err := os.Stat(r.manager.path(grubConfigPath)); os.IsNotExist(err) && !r.staleWithdrawal {
			text = "menuentry 'Linux' --unrestricted {\n linux /vmlinuz root=/dev/sda1 ro quiet\n}\n"
		}
		if r.generatedOverride != "" {
			text = r.generatedOverride
		}
		if r.bad {
			text = strings.Replace(text, "'Linux (recovery mode)'", "'Linux (recovery mode)' --unrestricted", 1)
		}
		if err := os.WriteFile(r.manager.path(bootGeneratedConfigPath), []byte(text), 0600); err != nil {
			return "", err
		}
		if r.partial {
			if err := os.WriteFile(r.manager.path(bootGeneratedConfigPath+".new"), []byte("partial output"), 0600); err != nil {
				return "", err
			}
			return "", errors.New("generator failed after partial output")
		}
		return "", nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestBootGenerationFailureRestoresActualPreviousBootFiles(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-menu", true: "partial-generation"}[partial], func(t *testing.T) {
			m := bootPolicyFixture(t)
			r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m}
			m.Runner = r
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			put(t, m, bootGeneratedConfigPath+".new", []byte("administrator staging file"))
			before, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
			beforeNew, _ := os.ReadFile(m.path(bootGeneratedConfigPath + ".new"))
			beforeAuth, _ := os.ReadFile(m.path(grubConfigPath))
			m.Config.Policies.GRUB.PasswordHash = "grub.pbkdf2.sha512.10000.AAAA.BBBB"
			r.bad, r.partial = true, partial
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("invalid or failed boot generation was committed")
			}
			after, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
			afterNew, _ := os.ReadFile(m.path(bootGeneratedConfigPath + ".new"))
			afterAuth, _ := os.ReadFile(m.path(grubConfigPath))
			if !bytes.Equal(before, after) || !bytes.Equal(beforeNew, afterNew) || !bytes.Equal(beforeAuth, afterAuth) {
				t.Fatal("rollback did not restore actual old boot configuration, staging file and authentication script")
			}
			if r.updates != 2 {
				t.Fatalf("rollback reran the failing generator: %d updates", r.updates)
			}
			if _, err := os.Stat(m.journalPath()); !os.IsNotExist(err) {
				t.Fatal("successful rollback retained transaction journal")
			}
		})
	}
}

func TestBootSameConfigurationRepairsGeneratedRecoveryDrift(t *testing.T) {
	m := bootPolicyFixture(t)
	r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m}
	m.Runner = r
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	drifted := strings.Replace(testBootConfig(), "'Linux (recovery mode)'", "'Linux (recovery mode)' --unrestricted", 1)
	put(t, m, bootGeneratedConfigPath, []byte(drifted))
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("reapplying identical policy did not repair generated boot drift: %v", err)
	}
	if r.updates != 2 {
		t.Fatalf("drift did not regenerate GRUB: %d updates", r.updates)
	}
	if err := m.validateBootPolicy(context.Background()); err != nil {
		t.Fatalf("GRUB still drifted after repair: %v", err)
	}
}

func TestBootRecoveryDetectionUsesKernelArgumentsRegardlessOfTitle(t *testing.T) {
	for _, argument := range []string{"single", "1", "init=/bin/sh", "rdinit=/bin/sh", "systemd.unit=emergency.target", "rd.systemd.unit=rescue.target", "rd.break=pre-mount", "rd.shell", "systemd.debug_shell=1", "systemd.run=/bin/sh"} {
		t.Run(argument, func(t *testing.T) {
			m := bootPolicyFixture(t)
			text := strings.Replace(testBootConfig(), " ro quiet $vt_handoff", " ro "+argument, 1)
			if err := m.validateBootText(text, true); err == nil {
				t.Fatal("unrestricted normal title concealed a recovery or root execution argument")
			}
		})
	}
}

func TestBootWithdrawalValidatesGeneratedAuthenticationWasRemoved(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "stale-generated-config"}[stale], func(t *testing.T) {
			m := bootPolicyFixture(t)
			r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m}
			m.Runner = r
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
			m.Config.Policies.GRUB.Enabled = false
			m.Config.Policies.GRUB.ProtectSingleUser = false
			r.staleWithdrawal = stale
			_, err := m.Apply(context.Background())
			if !stale {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(m.path(grubConfigPath)); !os.IsNotExist(err) {
					t.Fatal("owned authentication generator was not removed")
				}
				generated, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
				if strings.Contains(string(generated), "anquan-admin") {
					t.Fatal("Agent authentication remained in generated boot configuration")
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "withdrawal did not remove") {
					t.Fatalf("stale generated authentication was silently accepted: %v", err)
				}
				after, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
				if !bytes.Equal(before, after) {
					t.Fatal("failed withdrawal did not restore prior boot configuration")
				}
				if _, err := os.Stat(m.path(grubConfigPath)); err != nil {
					t.Fatal("failed withdrawal did not restore authentication generator")
				}
			}
		})
	}
}

func TestBootWithdrawalPreservesReferencedAdministratorAuthentication(t *testing.T) {
	m := bootPolicyFixture(t)
	r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m}
	m.Runner = r
	put(t, m, grubConfigPath, []byte(bootAuthenticationScript(testBootHash)))
	if err := os.Chmod(m.path(grubConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.path(grubConfigPath))
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := m.loadManifest()
	if err != nil || manifest.ReferencedFiles[grubConfigPath] == "" || manifest.Files[grubConfigPath] != "" {
		t.Fatalf("administrator authentication was incorrectly owned: %+v, %v", manifest, err)
	}
	m.Config.Policies.GRUB.Enabled = false
	m.Config.Policies.GRUB.ProtectSingleUser = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("external authentication must not be removed or treated as an owned withdrawal failure: %v", err)
	}
	after, _ := os.ReadFile(m.path(grubConfigPath))
	if !bytes.Equal(before, after) {
		t.Fatal("withdrawing policy modified administrator-owned authentication")
	}
	generated, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
	if !strings.Contains(string(generated), "password_pbkdf2 anquan-admin") {
		t.Fatal("fixture lost retained external authentication")
	}
}

func TestBootLegacyRecoveryRegeneratesOldPolicyWithoutComparingNewHash(t *testing.T) {
	m := bootPolicyFixture(t)
	r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m, generatedOverride: testBootConfig()}
	m.Runner = r
	m.Config.Policies.GRUB.PasswordHash = "grub.pbkdf2.sha512.10000.AAAA.BBBB"
	put(t, m, bootGeneratedConfigPath, []byte("partial menu from interrupted new policy"))
	journal := transactionJournal{Previous: manifest{Files: map[string]string{grubConfigPath: "old"}}, Next: manifest{Files: map[string]string{grubConfigPath: "new"}}}
	ctx, err := m.bootRecoveryContext(context.Background(), journal)
	if err != nil || !isBootRollback(ctx) || r.updates != 1 {
		t.Fatalf("legacy recovery did not regenerate restored old generator scripts: %d, %v", r.updates, err)
	}
	actual, _ := os.ReadFile(m.path(bootGeneratedConfigPath))
	if string(actual) != testBootConfig() {
		t.Fatal("legacy recovery did not restore the old generated menu")
	}
}

func TestBootRecoveryWithExactSnapshotDoesNotRunGenerator(t *testing.T) {
	m := bootPolicyFixture(t)
	r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m, partial: true}
	m.Runner = r
	journal := transactionJournal{Before: []snapshot{{Path: bootGeneratedConfigPath, Exists: true}}, Previous: manifest{Files: map[string]string{grubConfigPath: "old"}}, Next: manifest{Files: map[string]string{grubConfigPath: "new"}}}
	ctx, err := m.bootRecoveryContext(context.Background(), journal)
	if err != nil || !isBootRollback(ctx) || r.updates != 0 {
		t.Fatalf("exact snapshot recovery incorrectly reran generator: %d, %v", r.updates, err)
	}
}

func TestBootLegacyRecoveryFailurePreservesJournal(t *testing.T) {
	m := bootPolicyFixture(t)
	r := &bootPolicyRunner{fakeRunner: m.Runner.(*fakeRunner), manager: m, partial: true}
	m.Runner = r
	journal := transactionJournal{Previous: manifest{Files: map[string]string{grubConfigPath: "old"}}, Next: manifest{Files: map[string]string{grubConfigPath: "new"}}}
	if err := writePrivateJSON(m.journalPath(), "security-transaction", journal); err != nil {
		t.Fatal(err)
	}
	if _, err := m.bootRecoveryContext(context.Background(), journal); err == nil {
		t.Fatal("legacy generator failure was accepted")
	}
	if _, err := os.Stat(m.journalPath()); err != nil {
		t.Fatal("failed legacy recovery lost its retry journal")
	}
}

func TestBootAuditRejectsMalformedExistingCredential(t *testing.T) {
	m := bootPolicyFixture(t)
	m.Config.Policies.Mode = "audit"
	m.Config.Policies.GRUB.PasswordHash = ""
	for _, invalid := range []string{"grub.pbkdf2.sha512.0.ABCD.EFAB", "grub.pbkdf2.sha512.10000.ABC.EFAB", "grub.pbkdf2.sha512.10000.ABCD.EFA", "grub.pbkdf2.sha512.4294967296.ABCD.EFAB"} {
		if err := m.validateBootText(strings.ReplaceAll(testBootConfig(), testBootHash, invalid), true); err == nil {
			t.Fatalf("existing unusable credential was falsely compliant: %s", invalid)
		}
	}
}
