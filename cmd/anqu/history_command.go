package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// The profile helper must never enter installation, decrypt configuration, or
// put command text in process arguments. The root service owns the log file.
func recordHistoryCommand(input io.Reader, stderr io.Writer, executable func() (string, error), request func(context.Context, string, string) error) int {
	const maxCommandBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(input, maxCommandBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCommandBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 || strings.TrimSpace(string(data)) == "" {
		fmt.Fprintln(stderr, "invalid or oversized command input")
		return 1
	}
	path, err := executable()
	if err != nil || !filepath.IsAbs(path) {
		fmt.Fprintln(stderr, "cannot locate installed command client")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := request(ctx, filepath.Dir(path), string(data)); err != nil {
		fmt.Fprintln(stderr, "command recording failed:", err)
		return 1
	}
	return 0
}
