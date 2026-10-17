package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHistoryRecoveryArchiveReusesIdenticalEncryptedState(t *testing.T) {
	c := historyTestConfig(t)
	put(t, c.History.Path, historyLine("private command"))
	if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}
	path := c.StateFile + ".commands"
	before := read(t, path)
	first, err := archiveHistoryCommandState(path)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		again, err := archiveHistoryCommandState(path)
		if err != nil || again != first {
			t.Fatalf("retry created another archive: first=%s again=%s err=%v", first, again, err)
		}
	}
	if len(historyRecoveryArchives(t, c)) != 1 || read(t, path) != before || read(t, first) != before {
		t.Fatal("archive retry changed the source state or duplicated its backup")
	}
	if info, err := os.Stat(first); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("archive is not a regular file: %v", err)
	}
}

func TestHistoryRecoveryArchivePreservesExistingConflicts(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "different_bytes", true: "directory"}[directory], func(t *testing.T) {
			c := historyTestConfig(t)
			put(t, c.History.Path, historyLine("ls"))
			if _, err := pollHistory(c, nil, func(Config, []historyEvent) error { return nil }); err != nil {
				t.Fatal(err)
			}
			path := c.StateFile + ".commands"
			before := read(t, path)
			archive, err := archiveHistoryCommandState(path)
			if err != nil {
				t.Fatal(err)
			}
			if directory {
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(archive, 0700); err != nil {
					t.Fatal(err)
				}
				put(t, filepath.Join(archive, "keep"), "existing data")
			} else {
				changed := []byte(before)
				changed[0] ^= 1
				if err := os.WriteFile(archive, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := archiveHistoryCommandState(path); err == nil || read(t, path) != before {
				t.Fatal("conflicting archive was accepted or command state changed")
			}
			if directory {
				if read(t, filepath.Join(archive, "keep")) != "existing data" {
					t.Fatal("existing archive directory was changed")
				}
			} else if read(t, archive) == before {
				t.Fatal("conflicting archive was overwritten")
			}
		})
	}
}
