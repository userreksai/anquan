package main

import (
	"flag"
	"fmt"
	"os"

	"anqu/internal/audit"
)

func main() {
	flags := flag.NewFlagSet("anqu", flag.ContinueOnError)
	configPath := flags.String("config", "/usr/local/anqu/config.yaml", "YAML configuration file (.yaml/.yml; legacy .json also supported)")
	check := flags.Bool("check-config", false, "validate configuration and file checks without collecting")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		os.Exit(1)
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(1)
	}
	cfg, err := audit.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("configuration OK")
		return
	}
	report, paths, err := audit.Run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("report=%s\nmetrics=%s\nlatest=%s\n", paths.JSON, paths.Prom, paths.Latest)
	fmt.Printf("md5: files=%d changes=%d; login_found=%t; existence: checked=%d missing=%d mismatch=%d; errors=%d\n",
		report.MD5.Scanned, len(report.MD5.Changes), report.Login.Record != nil,
		len(report.Existence.Items), report.Existence.Missing, report.Existence.TypeMismatch, len(report.Errors))
	if !report.Success {
		for _, item := range report.Errors {
			fmt.Fprintln(os.Stderr, item.Module+": "+item.Message)
		}
		os.Exit(1)
	}
	if len(report.MD5.Changes) > 0 || report.Existence.Missing > 0 || report.Existence.TypeMismatch > 0 {
		os.Exit(2)
	}
}
