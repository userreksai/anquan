package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func put(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func wantFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatalf("%s = %q, error %v; want %q", path, data, err, expected)
	}
}

func fixture(t *testing.T) (string, layout) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "usr", "local", "anquan")
	return filepath.Join(root, "upload", "renamed-agent"), layout{
		directory: directory, executable: filepath.Join(directory, "anquan"),
		script: filepath.Join(root, "usr", "local", "ssh-init.sh"), sshrc: filepath.Join(root, "etc", "ssh", "sshrc"),
		service: filepath.Join(root, "etc", "systemd", "system", ServiceName),
	}
}

func requireSymlinks(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("target", path); err != nil {
		t.Skipf("host does not permit symlink creation: %v", err)
	}
}

func TestInstallExecutableCopiesAndCanUpgradeWithoutTruncation(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "first binary")
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	if moved, err := installExecutable(source, paths.executable); err != nil || !moved {
		t.Fatalf("copy: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "first binary")
	put(t, source, "updated binary")
	if moved, err := installExecutable(source, paths.executable); err != nil || !moved {
		t.Fatalf("upgrade: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "updated binary")
	if moved, err := installExecutable(paths.executable, paths.executable); err != nil || moved {
		t.Fatalf("repeat: moved=%t err=%v", moved, err)
	}
	if _, err := installExecutable(filepath.Dir(source), paths.executable); err == nil {
		t.Fatal("directory accepted as executable")
	}
	wantFile(t, paths.executable, "updated binary")
	if runtime.GOOS == "linux" {
		info, _ := os.Stat(paths.executable)
		if info.Mode().Perm() != 0755 {
			t.Fatalf("executable permissions: %v", info.Mode())
		}
	}
}

func TestOptionalSettingsAreCopiedOnlyWhenAbsent(t *testing.T) {
	source, paths := fixture(t)
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.age", "config.master.age", "agent.connection.age", "agent.connection.json"} {
		from, to := filepath.Join(filepath.Dir(source), name), filepath.Join(paths.directory, name)
		put(t, from, "uploaded settings")
		if err := copyOptional(from, to); err != nil {
			t.Fatal(err)
		}
		wantFile(t, to, "uploaded settings")
		put(t, to, "installed settings")
		if err := copyOptional(from, to); err != nil {
			t.Fatal(err)
		}
		wantFile(t, to, "installed settings")
	}
	if err := copyOptional(filepath.Join(filepath.Dir(source), "absent"), filepath.Join(paths.directory, "absent")); err != nil {
		t.Fatal(err)
	}
}

func TestScriptReplacementPreservesEveryExistingVersion(t *testing.T) {
	_, paths := fixture(t)
	put(t, paths.script, "existing hook one\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.script, hook)
	wantFile(t, paths.script+".anquan.bak", "existing hook one\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.script + ".anquan.bak.1"); !os.IsNotExist(err) {
		t.Fatal("unchanged hook was backed up again")
	}
	put(t, paths.script, "existing hook two\n")
	if err := ensureScript(paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.script+".anquan.bak", "existing hook one\n")
	wantFile(t, paths.script+".anquan.bak.1", "existing hook two\n")
	wantFile(t, paths.script, hook)
}

func TestInstallFromArbitraryDirectoryAndRepeat(t *testing.T) {
	requireSymlinks(t)
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	put(t, filepath.Join(filepath.Dir(source), "config.age"), "encrypted configuration")
	moved, err := ensure(source, paths)
	if err != nil || !moved {
		t.Fatalf("install: moved=%t err=%v", moved, err)
	}
	wantFile(t, paths.executable, "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "encrypted configuration")
	wantFile(t, paths.script, hook)
	for _, name := range []string{"state", "logs", "textfile"} {
		if _, err := os.Lstat(filepath.Join(paths.directory, name)); !os.IsNotExist(err) {
			t.Fatalf("installation precreated unused runtime directory %s: %v", name, err)
		}
	}
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH link: %q %v", target, err)
	}
	if moved, err := ensure(paths.executable, paths); err != nil || moved {
		t.Fatalf("repeat: moved=%t err=%v", moved, err)
	}
	if _, err := os.Stat(paths.sshrc + ".anquan.bak"); !os.IsNotExist(err) {
		t.Fatal("matching SSH link was backed up")
	}
}

func TestUploadBackupCleanupDoesNotRemoveReplacements(t *testing.T) {
	for _, replacement := range []string{"file", "directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			if replacement == "symlink" {
				requireSymlinks(t)
			}
			backup := filepath.Join(t.TempDir(), "anquan.upload-reserved")
			put(t, backup, "uploaded agent")
			original, err := os.Lstat(backup)
			if err != nil {
				t.Fatal(err)
			}
			// Capture Windows' lazily loaded file identity before changing paths.
			if !os.SameFile(original, original) {
				t.Fatal("cannot capture upload backup identity")
			}
			if err := os.Rename(backup, backup+".original"); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "file":
				put(t, backup, "replacement file")
			case "directory":
				if err := os.Mkdir(backup, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(backup+".original", backup); err != nil {
					t.Fatal(err)
				}
			}
			if err := removeUploadedBackup(backup, original); err == nil || !strings.Contains(err.Error(), "changed before cleanup") {
				t.Fatalf("replacement cleanup error: %v", err)
			}
			if _, err := os.Lstat(backup); err != nil {
				t.Fatalf("replacement was removed: %v", err)
			}
			wantFile(t, backup+".original", "uploaded agent")
		})
	}
}

func TestUploadBackupCleanupOnlyRemovesReservedFile(t *testing.T) {
	root := t.TempDir()
	backup := filepath.Join(root, "anquan.upload-reserved")
	older := filepath.Join(root, "anquan.upload-existing")
	installed := filepath.Join(root, "anquan", "anquan")
	put(t, backup, "uploaded agent")
	put(t, older, "older backup")
	put(t, installed, "installed agent")
	original, err := os.Lstat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeUploadedBackup(backup, original); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatalf("reserved upload backup remains after cleanup: %v", err)
	}
	wantFile(t, older, "older backup")
	wantFile(t, installed, "installed agent")
	if err := removeUploadedBackup(backup, original); err != nil {
		t.Fatalf("already removed backup: %v", err)
	}
}

func TestExistingSSHRCIsPreservedBeforeLinking(t *testing.T) {
	requireSymlinks(t)
	_, paths := fixture(t)
	put(t, paths.sshrc, "existing SSH initialization\n")
	if err := ensureSSHRC(paths.sshrc, paths.script); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.sshrc+".anquan.bak", "existing SSH initialization\n")
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH link: %q %v", target, err)
	}
}

func TestRefuseSSHDirectoriesAndSymlinkedInstallationDirectory(t *testing.T) {
	_, paths := fixture(t)
	if err := os.MkdirAll(paths.script, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ensureScript(paths.script); err == nil {
		t.Fatal("directory replaced by hook")
	}
	info, err := os.Stat(paths.script)
	if err != nil || !info.IsDir() {
		t.Fatal("existing directory changed")
	}
	requireSymlinks(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "install")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectory(link); err == nil {
		t.Fatal("symlink accepted as installation directory")
	}
}

func TestUploadedExecutableCanMakeRoomForInstallationDirectory(t *testing.T) {
	_, paths := fixture(t)
	source := paths.directory
	put(t, source, "uploaded agent")
	original, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	// Windows loads the file identity lazily from its old name. Capture that
	// identity before the rename so the comparison remains valid afterward.
	if !os.SameFile(original, original) {
		t.Fatal("cannot capture uploaded executable identity")
	}
	put(t, source+".upload-existing", "older upload backup")
	settings := []string{"config.age", "config.master.age", "agent.connection.age", "agent.connection.json"}
	for _, name := range settings {
		put(t, filepath.Join(filepath.Dir(source), name), "uploaded "+name)
	}
	relocated, backup, err := clearUploadedDirectory(source, paths.directory, 0)
	if err != nil || backup == "" || relocated != backup || filepath.Dir(relocated) != filepath.Dir(source) {
		t.Fatalf("relocation source %q, backup %q, error %v", relocated, backup, err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("installation directory path still occupied: %v", err)
	}
	info, err := os.Stat(backup)
	if err != nil || !os.SameFile(original, info) {
		t.Fatalf("original executable not preserved as backup: %v", err)
	}
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	if installed, err := installExecutable(relocated, paths.executable); err != nil || !installed {
		t.Fatalf("install relocated upload: %t, %v", installed, err)
	}
	for _, name := range settings {
		if err := copyOptional(filepath.Join(filepath.Dir(relocated), name), filepath.Join(paths.directory, name)); err != nil {
			t.Fatal(err)
		}
		wantFile(t, filepath.Join(paths.directory, name), "uploaded "+name)
	}
	wantFile(t, paths.executable, "uploaded agent")
	wantFile(t, backup, "uploaded agent")
	wantFile(t, source+".upload-existing", "older upload backup")
}

func TestUploadedDirectoryRelocationRequiresRootAndPreservesUnrelatedFiles(t *testing.T) {
	for _, args := range [][]string{nil, {"-service"}} {
		t.Run(fmtArgs(args), func(t *testing.T) {
			_, paths := fixture(t)
			put(t, paths.directory, "uploaded agent")
			var commands [][]string
			ops := testOperations(t, &commands)
			ops.euid = func() int { return 1000 }
			if _, err := prepare(paths.directory, args, nil, paths, ops); err == nil || !strings.Contains(err.Error(), "requires root") {
				t.Fatalf("non-root relocation: %v", err)
			}
			wantFile(t, paths.directory, "uploaded agent")
			if backups, err := filepath.Glob(paths.directory + ".upload-*"); err != nil || len(backups) != 0 {
				t.Fatalf("non-root created backup reservations: %v, %v", backups, err)
			}
			if len(commands) != 0 {
				t.Fatalf("non-root called systemctl: %v", commands)
			}
		})
	}
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	put(t, paths.directory, "unrelated occupant")
	var commands [][]string
	if _, err := prepare(source, nil, nil, paths, testOperations(t, &commands)); err == nil || !strings.Contains(err.Error(), "another file") || !strings.Contains(err.Error(), "mv -i") {
		t.Fatalf("unrelated file conflict: %v", err)
	}
	wantFile(t, source, "uploaded agent")
	wantFile(t, paths.directory, "unrelated occupant")
	if backups, err := filepath.Glob(paths.directory + ".upload-*"); err != nil || len(backups) != 0 {
		t.Fatalf("unrelated file moved or backup reserved: %v, %v", backups, err)
	}
	if len(commands) != 0 {
		t.Fatalf("conflict called systemctl: %v", commands)
	}
}

func fmtArgs(args []string) string {
	if len(args) == 0 {
		return "no_arguments"
	}
	return strings.Join(args, "_")
}

func TestExistingInstallationDirectoryIsUntouched(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	put(t, filepath.Join(paths.directory, "config.age"), "installed configuration")
	relocated, backup, err := clearUploadedDirectory(source, paths.directory, 1000)
	if err != nil || relocated != source || backup != "" {
		t.Fatalf("existing directory: source %q backup %q error %v", relocated, backup, err)
	}
	wantFile(t, source, "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "installed configuration")
}

func TestHardLinkedUploadRetainsOriginalConfigurationDirectory(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	if err := os.MkdirAll(filepath.Dir(paths.directory), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, paths.directory); err != nil {
		t.Skipf("host does not permit hard links: %v", err)
	}
	put(t, filepath.Join(filepath.Dir(source), "config.age"), "upload directory settings")
	put(t, filepath.Join(filepath.Dir(paths.directory), "config.age"), "different parent settings")
	relocated, backup, err := clearUploadedDirectory(source, paths.directory, 0)
	if err != nil || relocated != source || backup == "" {
		t.Fatalf("hard link relocation: source %q backup %q error %v", relocated, backup, err)
	}
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	if _, err := installExecutable(relocated, paths.executable); err != nil {
		t.Fatal(err)
	}
	if err := copyOptional(filepath.Join(filepath.Dir(relocated), "config.age"), filepath.Join(paths.directory, "config.age")); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(paths.directory, "config.age"), "upload directory settings")
	wantFile(t, source, "uploaded agent")
	wantFile(t, backup, "uploaded agent")
}

func TestSymlinkedUploadOrInstallationDirectoryIsNeverRelocated(t *testing.T) {
	requireSymlinks(t)
	for _, linkDirectory := range []bool{false, true} {
		source, paths := fixture(t)
		if linkDirectory {
			put(t, source, "uploaded agent")
			if err := os.MkdirAll(filepath.Dir(paths.directory), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(source, paths.directory); err != nil {
				t.Fatal(err)
			}
		} else {
			put(t, paths.directory, "uploaded agent")
			if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(paths.directory, source); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := clearUploadedDirectory(source, paths.directory, 0); err == nil {
			t.Fatal("symbolic link accepted for relocation")
		}
		wantFile(t, source, "uploaded agent")
		wantFile(t, paths.directory, "uploaded agent")
	}
}

func TestInstallationFailureReportsPreservedUploadForRetry(t *testing.T) {
	_, paths := fixture(t)
	put(t, paths.directory, "uploaded agent")
	if err := os.MkdirAll(paths.script, 0755); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	_, err := prepare(paths.directory, nil, nil, paths, testOperations(t, &commands))
	backups, globErr := filepath.Glob(paths.directory + ".upload-*")
	if globErr != nil || len(backups) != 1 {
		t.Fatalf("missing retained upload backup: %v, %v", backups, globErr)
	}
	if err == nil || !strings.Contains(err.Error(), backups[0]) || !strings.Contains(err.Error(), "retry installation") {
		t.Fatalf("backup retry path missing from installation error: %v", err)
	}
	wantFile(t, backups[0], "uploaded agent")
	wantFile(t, paths.executable, "uploaded agent")
	if len(commands) != 0 {
		t.Fatalf("failed file installation called systemctl: %v", commands)
	}
}

func TestHardLinkedUploadFailureRetriesOriginalConfigurationLocation(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	if err := os.MkdirAll(filepath.Dir(paths.directory), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, paths.directory); err != nil {
		t.Skipf("host does not permit hard links: %v", err)
	}
	put(t, filepath.Join(filepath.Dir(source), "config.age"), "original upload settings")
	if err := os.MkdirAll(paths.script, 0755); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	_, err := prepare(source, nil, nil, paths, testOperations(t, &commands))
	backups, globErr := filepath.Glob(paths.directory + ".upload-*")
	if globErr != nil || len(backups) != 1 {
		t.Fatalf("missing retained hard-linked upload: %v, %v", backups, globErr)
	}
	if err == nil || !strings.Contains(err.Error(), "preserved at "+backups[0]) || !strings.Contains(err.Error(), "run "+source+" to retry") {
		t.Fatalf("retry lost original upload configuration location: %v", err)
	}
	wantFile(t, source, "uploaded agent")
	wantFile(t, backups[0], "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "original upload settings")
	if len(commands) != 0 {
		t.Fatalf("failed installation called systemctl: %v", commands)
	}
}
