package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/install"
)

func TestCommandClientPassesStdinToServiceWithoutChangingText(t *testing.T) {
	const command = "printf '%s\\n' 'history and brackets [x]'\nsecond line"
	var stderr bytes.Buffer
	called := false
	installedPath := filepath.Join(t.TempDir(), "anquan")
	code := recordHistoryCommand(strings.NewReader(command), &stderr, func() (string, error) { return installedPath, nil }, func(ctx context.Context, base, text string) error {
		called = true
		if base != filepath.Dir(installedPath) || text != command {
			t.Fatalf("wrong command request: %q %q", base, text)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("command client has no bounded deadline")
		}
		return nil
	})
	if code != 0 || !called || stderr.Len() != 0 {
		t.Fatalf("command client: code=%d called=%t error=%s", code, called, stderr.String())
	}
}

func TestCommandClientRejectsBadInputBeforeLookingUpInstallation(t *testing.T) {
	for _, input := range []string{"", " \n", "bad\x00command", "\xff", strings.Repeat("x", (64<<10)+1)} {
		code := recordHistoryCommand(strings.NewReader(input), io.Discard, func() (string, error) { t.Fatal("invalid input resolved executable"); return "", nil }, func(context.Context, string, string) error { t.Fatal("invalid input reached service"); return nil })
		if code != 1 {
			t.Fatalf("invalid command accepted: length=%d", len(input))
		}
	}
}

func TestCommandClientServiceFailureDoesNotFallBack(t *testing.T) {
	var stderr bytes.Buffer
	installedPath := filepath.Join(t.TempDir(), "anquan")
	code := recordHistoryCommand(strings.NewReader("echo probe"), &stderr, func() (string, error) { return installedPath, nil }, func(context.Context, string, string) error { return errors.New("service disabled") })
	if code != 1 || !strings.Contains(stderr.String(), "service disabled") {
		t.Fatalf("failure did not remain explicit: %d %s", code, stderr.String())
	}
}

func TestCommandClientArgumentValidationPrecedesInstallation(t *testing.T) {
	code := runPrepared([]string{"-record-command", "insecure-argument"}, io.Discard, io.Discard,
		func() ([]byte, error) { t.Fatal("command mode decrypted configuration"); return nil, nil },
		func() (string, error) { t.Fatal("command mode resolved deployment path"); return "", nil },
		func(string, []string, io.Writer) (install.Preparation, error) {
			t.Fatal("command mode installed the program")
			return install.Preparation{}, nil
		})
	if code != 1 {
		t.Fatalf("command arguments accepted: %d", code)
	}
}
