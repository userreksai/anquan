//go:build !linux

package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHistoryCommandLogPortableNormalizationPreservesSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.log")
	const retained = "retained incomplete legacy record"
	if err := os.WriteFile(path, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := ensureHistoryCommandLog(path)
	if err != nil || created {
		t.Fatalf("existing log normalization: created=%v err=%v", created, err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || read(t, path) != retained {
		t.Fatalf("normalization changed the retained source: %v", err)
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != 0644 {
		t.Fatalf("normalized mode=%o, want 0644", after.Mode().Perm())
	}
}
