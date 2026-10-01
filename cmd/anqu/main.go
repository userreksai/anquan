package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"anqu/internal/audit"
	"anqu/internal/sealed"
)

const version = "0.3.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, sealed.Config, os.Executable))
}

// Agent nodes have no external configuration input or configuration-export API.
// Detailed audit findings remain in the report files, as requested by the operator.
func run(args []string, stdout, stderr io.Writer, load func() ([]byte, error), executable func() (string, error)) int {
	flags := flag.NewFlagSet("anqu", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print program version")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: anqu [-version]\nRuns one audit using configuration embedded on the build server.")
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
	data, err := load()
	if err != nil {
		fmt.Fprintln(stderr, "embedded configuration unavailable; rebuild this agent using anqu-build on the build server")
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
		fmt.Fprintln(stderr, "invalid embedded configuration; rebuild this agent on the build server")
		return 1
	}
	// Erase the decrypted source buffer as soon as parsing completes. Parsed Go
	// values necessarily remain in process memory while the audit runs.
	clear(data)
	report, _, err := audit.Run(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "audit could not complete; check output access and task status")
		return 1
	}
	if !report.Success {
		fmt.Fprintf(stderr, "audit collection failed (%d errors); see generated report\n", len(report.Errors))
		return 1
	}
	if len(report.MD5.Changes) > 0 || report.Existence.Missing > 0 || report.Existence.TypeMismatch > 0 {
		return 2
	}
	return 0
}
