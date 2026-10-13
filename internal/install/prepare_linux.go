//go:build linux

package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Prepare installs from any upload directory. A no-argument deployment starts
// the systemd service and returns; explicit run modes replace the process with
// the installed binary so os.Executable and config.age resolve consistently.
func Prepare(path string, args []string, writer io.Writer) (Preparation, error) {
	return prepare(path, args, writer, production, runtimeOperations{
		euid: os.Geteuid, systemctl: runSystemctl, exec: syscall.Exec,
	})
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s failed: %w; %s", strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return nil
}

func lockInstallation(directory string) (func(), error) {
	f, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another installation is in progress: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
