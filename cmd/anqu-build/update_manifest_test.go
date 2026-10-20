package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateManifestIdentifiesExactExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anquan")
	if err := os.WriteFile(path, []byte("abc"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := executableManifest(path, "0.7.3", "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version, GOOS, GOARCH, SHA256 string
		Size                          int64
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "0.7.3" || got.GOOS != "linux" || got.GOARCH != "arm64" || got.Size != 3 || got.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("incorrect release metadata: %s", data)
	}
}

func TestUpdateManifestUsesTargetCheckoutVersion(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "cmd", "anqu")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("package main\nconst version = \"0.8.9\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if version, err := sourceVersion(root); err != nil || version != "0.8.9" {
		t.Fatalf("checkout version=%q, err=%v", version, err)
	}
	if err := os.WriteFile(path, []byte("package main\nvar version = lookup()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceVersion(root); err == nil || !strings.Contains(err.Error(), "literal version") {
		t.Fatalf("dynamic version must not produce ambiguous metadata: %v", err)
	}
}
