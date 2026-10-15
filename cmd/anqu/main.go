package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"anqu/internal/audit"
	"anqu/internal/defaults"
	"anqu/internal/install"
	"anqu/internal/sealed"
)

const version = "0.6.9"

func main() {
	os.Exit(runPrepared(os.Args[1:], os.Stdout, os.Stderr, sealed.Config, os.Executable, install.Prepare))
}

// Agent nodes bootstrap from deployment settings or optional config.age.
// Single checks keep local logs without terminal output; services also log to stdout.
func runPrepared(args []string, stdout, stderr io.Writer, load func() ([]byte, error), executable func() (string, error), prepare func(string, []string, io.Writer) (install.Preparation, error)) int {
	return runPreparedWithSSH(args, stdout, stderr, load, executable, prepare, audit.RequestSSHExecution, audit.CurrentSSHExecutionCaller, installedSSHEntry)
}

func runPreparedWithSSH(args []string, stdout, stderr io.Writer, load func() ([]byte, error), executable func() (string, error), prepare func(string, []string, io.Writer) (install.Preparation, error), requestSSH func(context.Context, string, audit.SSHExecutionRequest) error, currentCaller func() (audit.SSHExecutionCaller, error), isInstalled func(string) bool) int {
	flags := flag.NewFlagSet("anqu", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print program version")
	service := flags.Bool("service", false, "run continuously using setup.interval_seconds")
	scan := flags.Bool("scan", false, "run one complete file/process audit")
	sshReport := flags.Bool("ssh-report", false, "report the current SSH login once for this invocation")
	master := flags.String("master", os.Getenv("ANQUAN_MASTER"), "configuration Master hostname or IP, optionally comma-separated (TCP port defaults to 55556); env ANQUAN_MASTER; fresh nodes default to "+defaults.MasterAddress+"; independent of YAML UDP server list")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: anqu [-service | -scan | -ssh-report] [-master HOST[:PORT]] [-version]\nOn a fresh Linux node, run as root without arguments to install and start agent.service using "+defaults.MasterAddress+". At the installed path, no arguments report one SSH login per invocation through agent.service; use -scan for a full audit. Use -master / ANQUAN_MASTER for explicit TCP configuration delivery. YAML server controls UDP reporting only. Without an audit configuration, -service waits for platform assignment without scanning.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 1
	}
	if *showVersion {
		fmt.Fprintln(stdout, "anqu "+version)
		return 0
	}
	if (*service && (*scan || *sshReport)) || (*scan && *sshReport) {
		fmt.Fprintln(stderr, "-service, -scan and -ssh-report cannot be combined")
		return 1
	}
	path, err := executable()
	if err != nil {
		fmt.Fprintln(stderr, "cannot locate executable directory")
		return 1
	}
	if *sshReport || (len(args) == 0 && isInstalled(path)) {
		return reportSSHExecution(path, *master, stderr, load, requestSSH, currentCaller)
	}
	prepared, err := prepare(path, args, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "agent installation failed:", err)
		return 1
	}
	if prepared.InstallOnly {
		return 0
	}
	path = prepared.Path
	if !*service {
		stdout, stderr = io.Discard, io.Discard
	}
	baseDir := filepath.Dir(path)
	data, err := load()
	defer clear(data)
	var cfg audit.Config
	if err == nil {
		cfg, err = audit.ParseConfig(data, baseDir)
		if err != nil {
			fmt.Fprintln(stderr, "invalid encrypted YAML configuration; correct and encrypt config.age again")
			return 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "encrypted configuration unavailable; check config.age beside the agent and its matching public key")
		return 1
	}
	// Erase the decrypted source buffer as soon as parsing completes. Parsed Go
	// values necessarily remain in process memory while the audit runs.
	clear(data)
	cfg, err = audit.BootstrapConfig(cfg, baseDir, *master)
	if err != nil {
		fmt.Fprintln(stderr, "invalid bootstrap settings:", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	delivery := audit.NewConfigDelivery(cfg, baseDir, version)
	if cached, err := delivery.CachedConfig(); err == nil {
		cfg = cached
	} else {
		fmt.Fprintln(stderr, "master configuration cache unavailable; retaining local configuration or waiting for assignment")
	}
	if *service {
		if err := audit.ServeWithConfigDelivery(ctx, cfg, stdout, version, delivery); err != nil {
			fmt.Fprintln(stderr, "service failed:", err)
			return 1
		}
		return 0
	}
	syncCtx, cancelSync := context.WithTimeout(ctx, 3*time.Second)
	cfg, _ = delivery.Sync(syncCtx)
	cancelSync()
	if cfg.WaitingForConfig() {
		return 1
	}
	if err := audit.LifecycleLog(cfg, stdout, "agent_started", map[string]any{"version": version, "pid": os.Getpid(), "mode": "once"}); err != nil {
		fmt.Fprintln(stderr, "cannot write startup log:", err)
		return 1
	}
	report, _, err := audit.RunWithWriter(audit.NewSession(cfg), stdout)
	if err != nil {
		fmt.Fprintln(stderr, "audit could not complete; check output access and task status")
		return 1
	}
	if !report.Success {
		fmt.Fprintf(stderr, "audit collection failed (%d errors); see agent log\n", len(report.Errors))
		return 1
	}
	if _, err := audit.PollHistory(cfg, stdout); err != nil {
		_ = audit.LifecycleLog(cfg, stdout, "history_error", map[string]string{"error": err.Error()})
		return 1
	}
	if len(report.Alerts) > 0 {
		return 2
	}
	return 0
}
