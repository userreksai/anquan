package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"anqu/internal/audit"
	"anqu/internal/sealed"
)

const version = "0.6.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, sealed.Config, os.Executable))
}

// Agent nodes read config.age beside the executable; no plaintext config API.
// Single checks keep local logs without terminal output; services also log to stdout.
func run(args []string, stdout, stderr io.Writer, load func() ([]byte, error), executable func() (string, error)) int {
	flags := flag.NewFlagSet("anqu", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print program version")
	service := flags.Bool("service", false, "run continuously using setup.interval_seconds")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: anqu [-service] [-version]\nReads config.age beside the executable. Runs one silent check by default; -service checks immediately and periodically.")
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
	if !*service {
		stdout, stderr = io.Discard, io.Discard
	}
	data, err := load()
	if err != nil {
		fmt.Fprintln(stderr, "encrypted configuration unavailable; check config.age beside the agent and its matching public key")
		return 1
	}
	defer clear(data)
	path, err := executable()
	if err != nil {
		fmt.Fprintln(stderr, "cannot locate executable directory")
		return 1
	}
	cfg, err := audit.ParseConfig(data, filepath.Dir(path))
	if err != nil {
		fmt.Fprintln(stderr, "invalid encrypted YAML configuration; correct and encrypt config.age again")
		return 1
	}
	// Erase the decrypted source buffer as soon as parsing completes. Parsed Go
	// values necessarily remain in process memory while the audit runs.
	clear(data)
	if *service {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := audit.Serve(ctx, cfg, stdout, version); err != nil {
			fmt.Fprintln(stderr, "service failed:", err)
			return 1
		}
		return 0
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
		fmt.Fprintf(stderr, "audit collection failed (%d errors); see generated report\n", len(report.Errors))
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
