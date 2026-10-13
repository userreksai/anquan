// Package install prepares the fixed Linux agent location, SSH login hook,
// and the continuous systemd service on a new deployment.
package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const Directory = "/usr/local/anquan"
const Executable = Directory + "/anquan"
const SSHScript = "/usr/local/ssh-init.sh"
const SSHRC = "/etc/ssh/sshrc"
const Service = "/etc/systemd/system/agent.service"
const ServiceName = "agent.service"
const hook = "#!/bin/sh\n" + Executable + " </dev/null >/dev/null 2>&1\n"

type layout struct {
	directory, executable, script, sshrc, service string
}

var production = layout{Directory, Executable, SSHScript, SSHRC, Service}

type Preparation struct {
	Path        string
	InstallOnly bool
}

// ensure is idempotent, and stages replacements on the destination filesystem.
// Existing settings take precedence over settings beside a newly uploaded binary.
func ensure(source string, paths layout) (relocated bool, err error) {
	if err := ensureDirectory(paths.directory); err != nil {
		return false, err
	}
	unlock, err := lockInstallation(paths.directory)
	if err != nil {
		return false, err
	}
	defer unlock()
	for _, name := range []string{"state", "logs", "textfile"} {
		if err := ensureDirectory(filepath.Join(paths.directory, name)); err != nil {
			return false, err
		}
	}
	relocated, err = installExecutable(source, paths.executable)
	if err != nil {
		return false, err
	}
	if relocated {
		for _, name := range []string{"config.age", "config.master.age", "agent.connection.age", "agent.connection.json"} {
			if err := copyOptional(filepath.Join(filepath.Dir(source), name), filepath.Join(paths.directory, name)); err != nil {
				return false, err
			}
		}
	}
	if err := ensureScript(paths.script); err != nil {
		return false, err
	}
	if err := ensureSSHRC(paths.sshrc, paths.script); err != nil {
		return false, err
	}
	return relocated, nil
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("create installation directory (first deployment requires root): %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("installation directory must be a real directory: %s", path)
	}
	return nil
}

func installExecutable(source, target string) (bool, error) {
	info, err := os.Stat(source)
	if err != nil || !info.Mode().IsRegular() {
		return false, fmt.Errorf("agent executable must be a readable regular file: %s", source)
	}
	if targetInfo, err := os.Lstat(target); err == nil {
		if !targetInfo.Mode().IsRegular() {
			return false, fmt.Errorf("installed executable must be a regular file: %s", target)
		}
		if os.SameFile(info, targetInfo) {
			return false, ensureMode(target, targetInfo, 0755)
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := copyFile(source, target, 0755); err != nil {
		return false, fmt.Errorf("install agent (first deployment requires root): %w", err)
	}
	return true, nil
}

func copyOptional(source, target string) error {
	if _, err := os.Lstat(target); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(source); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := copyFile(source, target, 0600); err != nil {
		return fmt.Errorf("copy optional agent settings: %w", err)
	}
	return nil
}

func copyFile(source, target string, mode os.FileMode) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file: %s", source)
	}
	stage, err := stageFile(target, f, mode)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	return os.Rename(stage, target)
}

func ensureScript(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode().IsRegular() {
		// Bound the read even if an unrelated local hook is unexpectedly large.
		if info.Size() == int64(len(hook)) {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if bytes.Equal(data, []byte(hook)) {
				return ensureMode(path, info, 0755)
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	stage, err := stageFile(path, bytes.NewReader([]byte(hook)), 0755)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	return replaceWithBackup(stage, path)
}

func ensureSSHRC(path, target string) error {
	if current, err := os.Readlink(path); err == nil && current == target {
		return nil
	}
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	// Reserve a unique staging name in the same directory before creating a link.
	f, err := os.CreateTemp(filepath.Dir(path), ".anquan-sshrc-*")
	if err != nil {
		return err
	}
	stage := f.Name()
	_ = f.Close()
	defer os.Remove(stage)
	if err := os.Remove(stage); err != nil {
		return err
	}
	if err := os.Symlink(target, stage); err != nil {
		return fmt.Errorf("create SSH login hook: %w", err)
	}
	return replaceWithBackup(stage, path)
}

func stageFile(target string, reader io.Reader, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), ".anquan-install-*")
	if err != nil {
		return "", err
	}
	stage := f.Name()
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(stage)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if _, err := io.Copy(f, reader); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	committed = true
	return stage, nil
}

func replaceWithBackup(stage, target string) error {
	info, err := os.Lstat(target)
	backup := ""
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("refusing to replace directory with installed file: %s", target)
		}
		for i := 0; ; i++ {
			backup = target + ".anquan.bak"
			if i > 0 {
				backup = fmt.Sprintf("%s.anquan.bak.%d", target, i)
			}
			if _, err := os.Lstat(backup); os.IsNotExist(err) {
				break
			} else if err != nil {
				return err
			}
		}
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("preserve existing installed file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stage, target); err != nil {
		if backup != "" {
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("install file: %v; restore original from %s: %w", err, backup, restoreErr)
			}
		}
		return err
	}
	return nil
}

func ensureMode(path string, info os.FileInfo, mode os.FileMode) error {
	if info.Mode().Perm() == mode {
		return nil
	}
	return os.Chmod(path, mode)
}
