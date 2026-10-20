package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"anqu/internal/install"
)

func TestInternalUpdateHelperRejectsArbitraryJournalBeforePreparation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPrepared([]string{"-update-helper", t.TempDir() + "/journal.json"}, &stdout, &stderr,
		func() ([]byte, error) { t.Fatal("helper loaded user configuration"); return nil, nil },
		func() (string, error) { t.Fatal("helper used deployment executable resolution"); return "", nil },
		func(string, []string, io.Writer) (install.Preparation, error) {
			t.Fatal("helper performed installation preparation")
			return install.Preparation{}, nil
		})
	if code != 1 || !strings.Contains(stderr.String(), "root-owned installed update journal") {
		t.Fatalf("helper rejection: %d %q", code, stderr.String())
	}
}

func TestVersionProbeDoesNotPrepareOrLoadConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPrepared([]string{"-version"}, &stdout, &stderr,
		func() ([]byte, error) { t.Fatal("version loaded configuration"); return nil, nil },
		func() (string, error) { t.Fatal("version resolved installation path"); return "", nil },
		func(string, []string, io.Writer) (install.Preparation, error) {
			t.Fatal("version prepared installation")
			return install.Preparation{}, nil
		})
	if code != 0 || strings.TrimSpace(stdout.String()) != "anqu "+version {
		t.Fatalf("version: %d %q %q", code, stdout.String(), stderr.String())
	}
}
