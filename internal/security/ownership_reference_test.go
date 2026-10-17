package security

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const referenceCompressPath = "/etc/anquan/tetragon.conf.d/export-file-compress"

func referenceDesiredFiles(t *testing.T, m *Manager) map[string]managedFile {
	t.Helper()
	files, _, err := m.desiredFiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func putReferenceFile(t *testing.T, m *Manager, path string, f managedFile) os.FileInfo {
	t.Helper()
	put(t, m, path, f.Data)
	if err := os.Chmod(m.path(path), f.Mode); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(m.path(path), old, old); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(m.path(path))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func assertReferenceUnchanged(t *testing.T, m *Manager, path string, f managedFile, before os.FileInfo) {
	t.Helper()
	raw, err := os.ReadFile(m.path(path))
	if err != nil || !bytes.Equal(raw, f.Data) {
		t.Fatalf("referenced file %s changed: %q, %v", path, raw, err)
	}
	after, err := os.Stat(m.path(path))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("referenced file %s was rewritten", path)
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != f.Mode.Perm() {
		t.Fatalf("referenced file %s permissions changed: %v", path, after.Mode())
	}
}

func assertNoReferenceTransaction(t *testing.T, m *Manager) {
	t.Helper()
	for _, path := range []string{m.manifestPath(), m.journalPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("rejected configuration left state %s: %v", path, err)
		}
	}
}

func TestApplyReferencesIdenticalTetragonFilesAcrossRestart(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	desired := referenceDesiredFiles(t, m)
	before := map[string]os.FileInfo{}
	for path, f := range desired {
		before[path] = putReferenceFile(t, m, path, f)
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("identical Tetragon residual files rejected: %v", err)
	}
	state, err := m.loadManifest()
	if err != nil {
		t.Fatal(err)
	}
	for path, f := range desired {
		if state.ReferencedFiles[path] != hashString(string(f.Data)) || state.Files[path] != "" {
			t.Fatalf("residual file %s was not recorded as a reference: %+v", path, state)
		}
		assertReferenceUnchanged(t, m, path, f, before[path])
	}
	manifestBefore, err := os.ReadFile(m.manifestPath())
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(m.Config, m.OutputDir)
	m2.RootDir, m2.Runner = m.RootDir, m.Runner
	persisted, err := m2.loadManifest()
	if err != nil || len(persisted.ReferencedFiles) != len(desired) {
		t.Fatalf("reference ownership did not survive Manager recreation: %+v, %v", persisted, err)
	}
	if _, err := m2.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifestAfter, err := os.ReadFile(m2.manifestPath())
	if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatalf("unchanged reference Apply rewrote the manifest: %v", err)
	}
	for path, f := range desired {
		assertReferenceUnchanged(t, m2, path, f, before[path])
	}
	m2.Config.Enabled = false
	if _, err := m2.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for path, f := range desired {
		assertReferenceUnchanged(t, m2, path, f, before[path])
	}
}

func TestApplyReferencesPartialTetragonResidualAndRemovesOnlyOwnedFiles(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	desired := referenceDesiredFiles(t, m)
	f := desired[referenceCompressPath]
	before := putReferenceFile(t, m, referenceCompressPath, f)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := m.loadManifest()
	if err != nil {
		t.Fatal(err)
	}
	for path, wanted := range desired {
		if path == referenceCompressPath {
			if state.ReferencedFiles[path] != hashString(string(wanted.Data)) || state.Files[path] != "" {
				t.Fatalf("residual file was granted write/delete ownership: %+v", state)
			}
		} else if state.ReferencedFiles[path] != "" || state.Files[path] != hashString(string(wanted.Data)) {
			t.Fatalf("Agent-created file %s is not owned: %+v", path, state)
		}
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertReferenceUnchanged(t, m, referenceCompressPath, f, before)
	for path := range desired {
		if path == referenceCompressPath {
			continue
		}
		if _, err := os.Stat(m.path(path)); !os.IsNotExist(err) {
			t.Fatalf("Agent-created file %s was not removed on disable: %v", path, err)
		}
	}
}

func TestReferencedSudoFileRejectsConfigurationChange(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true}})
	f := referenceDesiredFiles(t, m)[sudoConfigPath]
	before := putReferenceFile(t, m, sudoConfigPath, f)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(m.manifestPath())
	if err != nil {
		t.Fatal(err)
	}
	m.Config.Sudo.IOLogging = true
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("configuration change overwrote the referenced sudo file")
	}
	assertReferenceUnchanged(t, m, sudoConfigPath, f, before)
	manifestAfter, err := os.ReadFile(m.manifestPath())
	if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatalf("rejected sudo change committed a manifest: %v", err)
	}
}

func TestReferencedFileRejectsExternalContentChange(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	f := referenceDesiredFiles(t, m)[referenceCompressPath]
	putReferenceFile(t, m, referenceCompressPath, f)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed := []byte("true\n")
	put(t, m, referenceCompressPath, changed)
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("externally modified reference was silently repaired")
	}
	raw, err := os.ReadFile(m.path(referenceCompressPath))
	if err != nil || !bytes.Equal(raw, changed) {
		t.Fatalf("external reference changes overwritten: %q, %v", raw, err)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(m.path(referenceCompressPath))
	if err != nil || !bytes.Equal(raw, changed) {
		t.Fatalf("disable removed externally modified reference: %q, %v", raw, err)
	}
}

func TestMissingReferenceBecomesAgentOwnedAfterRecreation(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	f := referenceDesiredFiles(t, m)[referenceCompressPath]
	putReferenceFile(t, m, referenceCompressPath, f)
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.path(referenceCompressPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := m.loadManifest()
	if err != nil || state.ReferencedFiles[referenceCompressPath] != "" || state.Files[referenceCompressPath] == "" {
		t.Fatalf("recreated missing file did not become Agent-owned: %+v, %v", state, err)
	}
	raw, err := os.ReadFile(m.path(referenceCompressPath))
	if err != nil || !bytes.Equal(raw, f.Data) {
		t.Fatalf("missing reference not recreated: %q, %v", raw, err)
	}
	m.Config.Enabled = false
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.path(referenceCompressPath)); !os.IsNotExist(err) {
		t.Fatalf("recreated Agent-owned file survived disable: %v", err)
	}
}

func TestReferenceActivationFailureDoesNotCommitOrRewrite(t *testing.T) {
	m, r := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
	desired := referenceDesiredFiles(t, m)
	f := desired[referenceCompressPath]
	before := putReferenceFile(t, m, referenceCompressPath, f)
	activationErr := errors.New("injected Tetragon activation failure")
	failed := false
	r.fail = func(name string, args []string) error {
		if !failed && name == "systemctl" && strings.Join(args, " ") == "restart tetragon" {
			failed = true
			return activationErr
		}
		return nil
	}
	if _, err := m.Apply(context.Background()); !errors.Is(err, activationErr) {
		t.Fatalf("expected activation error, got %v", err)
	}
	assertReferenceUnchanged(t, m, referenceCompressPath, f, before)
	assertNoReferenceTransaction(t, m)
	for path := range desired {
		if path == referenceCompressPath {
			continue
		}
		if _, err := os.Stat(m.path(path)); !os.IsNotExist(err) {
			t.Fatalf("failed activation retained new file %s: %v", path, err)
		}
	}
}

func TestReferencePreflightRejectsConflictingFiles(t *testing.T) {
	for _, kind := range []string{"different-content", "directory", "different-permissions"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "different-permissions" && runtime.GOOS == "windows" {
				t.Skip("Windows does not represent Unix file permission bits")
			}
			m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
			f := referenceDesiredFiles(t, m)[referenceCompressPath]
			switch kind {
			case "different-content":
				put(t, m, referenceCompressPath, []byte("true\n"))
			case "directory":
				if err := os.MkdirAll(m.path(referenceCompressPath), 0755); err != nil {
					t.Fatal(err)
				}
			case "different-permissions":
				putReferenceFile(t, m, referenceCompressPath, f)
				if err := os.Chmod(m.path(referenceCompressPath), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("conflicting unowned path accepted")
			}
			assertNoReferenceTransaction(t, m)
			if kind == "different-content" {
				raw, err := os.ReadFile(m.path(referenceCompressPath))
				if err != nil || string(raw) != "true\n" {
					t.Fatalf("preflight modified conflicting bytes: %q, %v", raw, err)
				}
			}
		})
	}
}

func TestReferencePreflightRejectsSymlinkFilesAndParents(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		name := "file"
		if parentLink {
			name = "parent-directory"
		}
		t.Run(name, func(t *testing.T) {
			m, _ := testManager(t, Config{Enabled: true, Tetragon: TetragonConfig{Enabled: true}})
			f := referenceDesiredFiles(t, m)[referenceCompressPath]
			targetDir := t.TempDir()
			target := filepath.Join(targetDir, "export-file-compress")
			if err := os.WriteFile(target, f.Data, f.Mode); err != nil {
				t.Fatal(err)
			}
			link, linkTarget := m.path(referenceCompressPath), target
			if parentLink {
				link, linkTarget = filepath.Dir(link), targetDir
			}
			if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(linkTarget, link); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("identical bytes through symlink were accepted as a reference")
			}
			assertNoReferenceTransaction(t, m)
			raw, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(raw, f.Data) {
				t.Fatalf("symlink target changed: %q, %v", raw, err)
			}
		})
	}
}

func TestReferenceReapplyRejectsSymlinkReplacement(t *testing.T) {
	for _, parentLink := range []bool{false, true} {
		name := "file"
		if parentLink {
			name = "parent-directory"
		}
		t.Run(name, func(t *testing.T) {
			m, _ := testManager(t, Config{Enabled: true, Sudo: SudoConfig{Enabled: true}})
			f := referenceDesiredFiles(t, m)[sudoConfigPath]
			putReferenceFile(t, m, sudoConfigPath, f)
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			manifestBefore, err := os.ReadFile(m.manifestPath())
			if err != nil {
				t.Fatal(err)
			}
			targetDir := t.TempDir()
			target := filepath.Join(targetDir, filepath.Base(m.path(sudoConfigPath)))
			if err := os.WriteFile(target, f.Data, f.Mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(m.path(sudoConfigPath)); err != nil {
				t.Fatal(err)
			}
			link, linkTarget := m.path(sudoConfigPath), target
			if parentLink {
				link, linkTarget = filepath.Dir(link), targetDir
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(linkTarget, link); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			if _, err := m.Apply(context.Background()); err == nil {
				t.Fatal("idempotent Apply accepted a reference replaced with a symlink")
			}
			manifestAfter, err := os.ReadFile(m.manifestPath())
			if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
				t.Fatalf("symlink rejection modified ownership manifest: %v", err)
			}
			raw, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(raw, f.Data) {
				t.Fatalf("symlink replacement target changed: %q, %v", raw, err)
			}
		})
	}
}

func TestReferenceRechecksFilesCreatedAfterPreflight(t *testing.T) {
	for _, same := range []bool{true, false} {
		name := "identical-file-becomes-reference"
		if !same {
			name = "different-file-is-preserved-and-rejected"
		}
		t.Run(name, func(t *testing.T) {
			m, r := testManager(t, Config{
				Enabled:  true,
				Tetragon: TetragonConfig{Enabled: true},
				Policies: PolicyConfig{Mode: "enforce", DisableCtrlAltDel: true},
			})
			desired := referenceDesiredFiles(t, m)
			f := desired[referenceCompressPath]
			if !same {
				f.Data = []byte("true\n")
			}
			var before os.FileInfo
			r.fail = func(name string, args []string) error {
				if before == nil && name == "systemctl" && strings.Join(args, " ") == "is-enabled ctrl-alt-del.target" {
					before = putReferenceFile(t, m, referenceCompressPath, f)
				}
				return nil
			}
			_, err := m.Apply(context.Background())
			if before == nil {
				t.Fatal("test did not inject a file between preflight and file application")
			}
			assertReferenceUnchanged(t, m, referenceCompressPath, f, before)
			if !same {
				if err == nil {
					t.Fatal("file created after preflight was overwritten or silently accepted")
				}
				assertNoReferenceTransaction(t, m)
				for path := range desired {
					if path != referenceCompressPath {
						if _, statErr := os.Stat(m.path(path)); !os.IsNotExist(statErr) {
							t.Fatalf("rejected concurrent conflict retained new file %s: %v", path, statErr)
						}
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("identical file created after preflight rejected: %v", err)
			}
			state, err := m.loadManifest()
			if err != nil || state.Files[referenceCompressPath] != "" || state.ReferencedFiles[referenceCompressPath] != hashString(string(f.Data)) {
				t.Fatalf("file created after preflight gained write/delete ownership: %+v, %v", state, err)
			}
			m.Config.Enabled = false
			if _, err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertReferenceUnchanged(t, m, referenceCompressPath, f, before)
		})
	}
}
