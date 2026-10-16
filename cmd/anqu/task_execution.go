package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"anqu/internal/audit"
)

// Task execution is independent of installation and configuration delivery, so
// a cron command keeps running when the service or Master is unavailable.
func runTaskExecution(path, name string, args []string, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code, err := audit.RunRecordedTask(ctx, filepath.Dir(path), name, args, stdout, stderr)
	if err != nil && stderr != nil {
		fmt.Fprintln(stderr, "task execution recording:", err)
	}
	return code
}
