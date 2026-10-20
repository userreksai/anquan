//go:build linux

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func rootOwned(path string, directory bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func platformEligible(executable string) bool {
	if os.Geteuid() != 0 || filepath.Clean(executable) != InstalledExecutable || !rootOwned(filepath.Dir(executable), true) || !rootOwned(executable, false) {
		return false
	}
	for _, name := range []string{"systemctl", "systemd-run"} {
		if _, err := exec.LookPath(name); err != nil {
			return false
		}
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(cgroup), "\n") {
		if strings.HasSuffix(line, "/agent.service") {
			return true
		}
	}
	return false
}

func ensurePrivateDirectory(directory string) error {
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !rootOwned(directory, true) || info.Mode().Perm() != 0700 {
		return errors.New("self-update directory must be root-owned mode 0700")
	}
	return nil
}

func helperEligible(path string) bool {
	return os.Geteuid() == 0 && filepath.Clean(path) == filepath.Join(stateDirectory, "journal.json") && rootOwned(stateDirectory, true) && rootOwned(path, false) && rootOwned(filepath.Join(stateDirectory, "helper"), false)
}

func launchHelper(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := readJournal(stateDirectory)
	if err != nil {
		return err
	}
	// It must survive cancellation when this service is stopped by its helper.
	launchCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(launchCtx, "systemd-run", "--quiet", "--no-block", "--collect", "--unit=anquan-update-"+state.JobID, "--property=Type=exec", "--property=RuntimeMaxSec=300", "--", filepath.Join(stateDirectory, "helper"), "-update-helper", path)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(output)))
	}
	// A queued transient unit is not enough: confirm that our verified helper
	// entered its journal before declaring the handoff complete.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(filepath.Join(stateDirectory, "helper-started"))
		if err == nil && string(data) == state.JobID {
			return nil
		}
		select {
		case <-launchCtx.Done():
			return errors.New("detached update helper did not start")
		case <-ticker.C:
		}
	}
}

func serviceCommand(ctx context.Context, action string) error {
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "systemctl", action, "agent.service")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func probeVersion(ctx context.Context, path string) ([]byte, error) {
	return exec.CommandContext(ctx, path, "-version").Output()
}

func syncDirectoryFile(file *os.File) error    { return file.Sync() }
func privatePermissions(mode os.FileMode) bool { return mode.Perm()&0077 == 0 }

func updateHelperActive(jobID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "anquan-update-"+jobID+".service").Run() == nil
}
