package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"anqu/internal/audit"
	"anqu/internal/install"
)

func installedSSHEntry(path string) bool {
	if filepath.Clean(path) != filepath.Clean(install.Executable) {
		return false
	}
	// A fresh upload can already occupy the final executable path. Until its
	// service unit exists it still needs the normal first-install preparation.
	info, err := os.Stat(install.Service)
	return err == nil && info.Mode().IsRegular()
}

// The sshrc path must reach the root service before attempting installation,
// reading root-only configuration, synchronizing TCP settings or scanning files.
func reportSSHExecution(path, master string, stderr io.Writer, load func() ([]byte, error), requestSSH func(context.Context, string, audit.SSHExecutionRequest) error, currentCaller func() (audit.SSHExecutionCaller, error)) int {
	req, err := audit.NewSSHExecutionRequest(os.Getenv("SSH_CONNECTION"))
	if err != nil {
		fmt.Fprintln(stderr, "SSH execution report failed:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseDir := filepath.Dir(path)
	err = requestSSH(ctx, baseDir, req)
	if err == nil {
		return 0
	}
	if !errors.Is(err, audit.ErrSSHExecutionUnavailable) {
		fmt.Fprintln(stderr, "SSH execution report failed:", err)
		return 1
	}
	// Only root can safely use the last confirmed configuration if the service
	// is stopped. An application-level rejection is never retried as a fallback.
	caller, callerErr := currentCaller()
	if callerErr != nil || caller.UID != 0 {
		fmt.Fprintln(stderr, "SSH execution report failed: agent.service is unavailable; start the configured root service")
		return 1
	}
	data, loadErr := load()
	defer clear(data)
	var cfg audit.Config
	if loadErr == nil {
		cfg, err = audit.ParseConfig(data, baseDir)
		clear(data)
		if err != nil {
			fmt.Fprintln(stderr, "SSH execution report failed: invalid local configuration")
			return 1
		}
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		fmt.Fprintln(stderr, "SSH execution report failed: local configuration unavailable")
		return 1
	}
	cfg, err = audit.BootstrapConfig(cfg, baseDir, master)
	if err == nil {
		cfg, err = audit.NewConfigDelivery(cfg, baseDir, version).CachedConfig()
	}
	if err == nil {
		_, err = audit.ReportSSHExecution(ctx, cfg, nil, req, caller)
	}
	if err != nil {
		fmt.Fprintln(stderr, "SSH execution report failed:", err)
		return 1
	}
	return 0
}
