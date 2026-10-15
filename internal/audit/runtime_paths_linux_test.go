//go:build linux

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeDirectoryRejectsSymlinksWritableDirectoriesAndFiles(t *testing.T) {
	base := sshIPCBase(t)
	for _, kind := range []string{"symlink", "writable", "file", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(base, kind)
			switch kind {
			case "symlink":
				target := filepath.Join(base, "target")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "writable", "foreign-owner":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
				if kind == "writable" {
					if err := os.Chmod(path, 0777); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Chown(path, 65534, -1); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(path, []byte("preserve me"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := ensureRootRuntimeDirectory(path, 0755); err == nil {
				t.Fatal("unsafe runtime directory accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("unsafe runtime entry was changed: %v", err)
			}
			if kind == "symlink" {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatalf("symlink target permissions were changed: %v", err)
				}
			}
			if kind == "file" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserve me" {
					t.Fatalf("unrelated runtime file was changed: %q, %v", data, err)
				}
			}
		})
	}
}

func TestRuntimeDirectoryCreatesAndReusesSecureDirectory(t *testing.T) {
	path := filepath.Join(sshIPCBase(t), "locks")
	if err := ensureRootRuntimeDirectory(path, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Perm() != 0700 {
		t.Fatalf("runtime lock directory permissions are wrong: %v", err)
	}
	if err := ensureRootRuntimeDirectory(path, 0700); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("runtime directory inode was replaced: %v", err)
	}
}

func TestSystemRuntimeValidationStopsAtUnsafeParentAndRejectsEscapes(t *testing.T) {
	wantErr := errors.New("unsafe parent")
	var visited []string
	err := walkSystemRuntimeDirectory(filepath.Join(systemAgentRuntimeDirectory, ".anqu-service-locks", "state", "md5.json"), func(path string, _ bool) error {
		visited = append(visited, path)
		if path == systemAgentRuntimeDirectory {
			return wantErr
		}
		return nil
	})
	if !errors.Is(err, wantErr) || len(visited) != 2 || visited[0] != "/run" || visited[1] != systemAgentRuntimeDirectory {
		t.Fatalf("runtime validation continued after unsafe parent: %v, %v", visited, err)
	}
	for _, path := range []string{"/run/anquan-other/locks", "/run/anquan/../elsewhere"} {
		visited = nil
		if err := walkSystemRuntimeDirectory(path, func(path string, _ bool) error { visited = append(visited, path); return nil }); err == nil || len(visited) != 0 {
			t.Fatalf("runtime traversal escaped its root: %q: %v, %v", path, visited, err)
		}
	}
}
