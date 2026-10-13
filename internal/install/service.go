package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"anqu/internal/defaults"
)

type runtimeOperations struct {
	euid      func() int
	systemctl func(...string) error
	exec      func(string, []string, []string) error
}

const serviceInstalling = ".agent-service-installing"

// prepare installs on Linux. Its operations are injected so tests never invoke
// the host's service manager or replace the testing process.
func prepare(path string, args []string, writer io.Writer, paths layout, ops runtimeOperations) (Preparation, error) {
	_, serviceErr := os.Lstat(paths.service)
	if serviceErr != nil && !os.IsNotExist(serviceErr) {
		return Preparation{}, fmt.Errorf("inspect systemd service: %w", serviceErr)
	}
	serviceExists := serviceErr == nil
	pending := false
	if len(args) == 0 {
		var err error
		pending, err = serviceInstallationPending(paths.directory)
		if err != nil {
			return Preparation{}, err
		}
	}
	// An installed no-argument invocation is still a one-shot SSH check. A
	// service invocation never tries to activate another systemd process.
	newDeployment := len(args) == 0 && (filepath.Clean(path) != filepath.Clean(paths.executable) || !serviceExists || pending)
	if newDeployment && ops.euid() != 0 {
		return Preparation{}, fmt.Errorf("first deployment requires root to install and start %s", ServiceName)
	}
	relocated, err := ensure(path, paths)
	if err != nil {
		return Preparation{}, err
	}
	if len(args) == 0 && (relocated || !serviceExists || pending) {
		if err := installService(paths, ops.systemctl, serviceExists); err != nil {
			return Preparation{}, err
		}
		if writer != nil {
			fmt.Fprintf(writer, "Installed %s; SSH login hook ready; %s enabled and started with Master %s.\n", paths.executable, ServiceName, defaults.MasterAddress)
		}
		return Preparation{Path: paths.executable, InstallOnly: true}, nil
	}
	if relocated && writer != nil {
		fmt.Fprintf(writer, "Installed %s; SSH login hook ready.\n", paths.executable)
	}
	if filepath.Clean(path) != filepath.Clean(paths.executable) {
		if err := ops.exec(paths.executable, append([]string{paths.executable}, args...), os.Environ()); err != nil {
			return Preparation{}, fmt.Errorf("start installed agent: %w", err)
		}
	}
	return Preparation{Path: paths.executable}, nil
}

func serviceInstallationPending(directory string) (bool, error) {
	path := filepath.Join(directory, serviceInstalling)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect service installation progress: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("service installation progress must be a regular file: %s", path)
	}
	return true, nil
}

func markServiceInstalling(directory string) error {
	if _, err := serviceInstallationPending(directory); err != nil {
		return err
	}
	path := filepath.Join(directory, serviceInstalling)
	stage, err := stageFile(path, bytes.NewReader([]byte(ServiceName+"\n")), 0600)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	return os.Rename(stage, path)
}

func serviceUnit(executable string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=Anquan Agent Scan
Wants=network-online.target
After=local-fs.target network-online.target
Conflicts=agent.timer anqu.service anqu-oneshot.service

[Service]
Type=simple
User=root
UMask=0022
WorkingDirectory=%s
Environment=ANQUAN_MASTER=%s
ExecStart=%s -service -master %s
Restart=on-failure
RestartSec=5
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, filepath.Dir(executable), defaults.MasterAddress, executable, defaults.MasterAddress))
}

func ensureService(path, executable string) error {
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	want := serviceUnit(executable)
	info, err := os.Lstat(path)
	if err == nil && info.Mode().IsRegular() && info.Size() == int64(len(want)) {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Equal(data, want) {
			return ensureMode(path, info, 0644)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	stage, err := stageFile(path, bytes.NewReader(want), 0644)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	return replaceWithBackup(stage, path)
}

func installService(paths layout, run func(...string) error, existed bool) error {
	unlock, err := lockInstallation(paths.directory)
	if err != nil {
		return err
	}
	err = markServiceInstalling(paths.directory)
	if err == nil {
		err = ensureService(paths.service, paths.executable)
	}
	unlock()
	if err != nil {
		return fmt.Errorf("install systemd service: %w", err)
	}
	// Release the installation lock before starting: the new service calls
	// Prepare itself while systemctl waits for the unit to start.
	if err := run("daemon-reload"); err != nil {
		return err
	}
	for _, name := range []string{"agent.timer", "anqu.timer"} {
		path := filepath.Join(filepath.Dir(paths.service), name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect legacy timer %s: %w", name, err)
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("legacy timer must be a regular file or symbolic link: %s", path)
		}
		if err := run("disable", "--now", name); err != nil {
			return err
		}
	}
	if err := run("enable", "--now", ServiceName); err != nil {
		return err
	}
	if existed {
		// enable --now leaves an already running service untouched. A newly
		// uploaded executable or replaced legacy unit requires a restart.
		if err := run("restart", ServiceName); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(paths.directory, serviceInstalling)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("finish service installation: %w", err)
	}
	return nil
}
