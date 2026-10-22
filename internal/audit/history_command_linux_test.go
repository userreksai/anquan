//go:build linux

package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func historyCommandRootTestDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("real command socket permissions require root; CI runs this test group with sudo")
	}
	dir, err := os.MkdirTemp("/run", "anquan-history-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func startHistoryCommandTestService(t *testing.T, dir, logPath string) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHistoryCommandsAt(ctx, dir, logPath, time.UTC) }()
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(HistoryCommandSocket(dir)); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0666 {
			return cancel, done
		}
		select {
		case err := <-done:
			t.Fatalf("command service failed to start: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	t.Fatal("command service did not start")
	return cancel, done
}

func stopHistoryCommandTestService(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("command service cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("command service did not join handlers on cancellation")
	}
}

func TestHistoryCommandRootIPC(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	path := filepath.Join(dir, "history.log")
	if err := os.WriteFile(path, []byte("retained old record\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cancel, done := startHistoryCommandTestService(t, dir, path)
	if err := RequestHistoryCommand(context.Background(), dir, "echo one\r\necho two"); err != nil {
		t.Fatal(err)
	}
	// Extra identity/path fields are rejected rather than trusted or ignored.
	conn, err := net.Dial("unix", HistoryCommandSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, "{\"command\":\"forged\",\"user\":\"nobody\"}\n")
	var response historyCommandResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil || response.Error == "" {
		t.Fatalf("identity injection accepted: %+v %v", response, err)
	}
	_ = conn.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "retained old record" {
		t.Fatalf("append changed existing bytes or injected records: %q", data)
	}
	account, err := user.LookupId("0")
	if err != nil {
		t.Fatal(err)
	}
	record, err := parseHistoryLine(lines[1], path, "test", 0, time.UTC)
	if err != nil || record.User != account.Username || record.Command != `echo one\r\necho two` {
		t.Fatalf("peer identity or escaped command incorrect: %+v %v", record, err)
	}
	if time.Since(record.CommandTime) < -time.Second || time.Since(record.CommandTime) > 5*time.Second {
		t.Fatalf("record did not use server time: %v", record.CommandTime)
	}
	// A client that never completes its frame must also be closed by shutdown.
	idle, err := net.Dial("unix", HistoryCommandSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	stopHistoryCommandTestService(t, cancel, done)
	if _, err := os.Lstat(HistoryCommandSocket(dir)); !os.IsNotExist(err) {
		t.Fatalf("service left its own socket behind: %v", err)
	}
	if err := RequestHistoryCommand(context.Background(), dir, "must not fallback"); err == nil {
		t.Fatal("stopped service unexpectedly accepted a command")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("unavailable service wrote through an implicit fallback")
	}
}

func TestHistoryCommandUnprivilegedClientHelper(t *testing.T) {
	if os.Getenv("ANQUAN_HISTORY_COMMAND_CHILD") != "1" {
		return
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "child unexpectedly retained root")
		os.Exit(2)
	}
	if err := RequestHistoryCommand(context.Background(), os.Getenv("ANQUAN_HISTORY_COMMAND_BASE"), "echo FROM_UNPRIVILEGED"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

func TestHistoryCommandRootAcceptsUnprivilegedPeer(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatalf("invalid nobody UID: %v", err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history.log")
	cancel, done := startHistoryCommandTestService(t, dir, path)
	defer stopHistoryCommandTestService(t, cancel, done)
	// A copied executable permits traversal without exposing Go's build cache.
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	clientPath := filepath.Join(dir, "client-test")
	output, err := os.OpenFile(clientPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	permissionErr := output.Chmod(0755)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || permissionErr != nil {
		t.Fatalf("copy client: %v %v %v", copyErr, closeErr, permissionErr)
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	cmd := exec.CommandContext(ctx, clientPath, "-test.run=^TestHistoryCommandUnprivilegedClientHelper$")
	cmd.Env = append(os.Environ(), "ANQUAN_HISTORY_COMMAND_CHILD=1", "ANQUAN_HISTORY_COMMAND_BASE="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ordinary user could not record through root service: %v %s", err, data)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := parseHistoryLine(string(data), path, "test", 0, time.UTC)
	if err != nil || record.User != account.Username || record.Command != "echo FROM_UNPRIVILEGED" {
		t.Fatalf("kernel peer UID not retained: %+v %v", record, err)
	}
	info, err := os.Stat(path)
	if err != nil || !verifyHistoryManagedOwner(info) || info.Mode().Perm() != 0644 {
		t.Fatalf("log ownership/permissions weakened: %v %v", info, err)
	}
}

func TestHistoryCommandRootLogSafety(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	path := filepath.Join(dir, "history.log")
	created, err := ensureHistoryCommandLog(path)
	if err != nil || !created {
		t.Fatalf("create log: %v %v", created, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("preserved\n"), 0600); err != nil {
		t.Fatal(err)
	}
	created, err = ensureHistoryCommandLog(path)
	if err != nil || created {
		t.Fatalf("existing log not retained: %v %v", created, err)
	}
	info, _ := os.Stat(path)
	if err := validHistoryCommandLog(info); err != nil {
		t.Fatalf("existing log was not normalized: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "preserved\n" {
		t.Fatal("existing bytes changed")
	}
	for _, mode := range []os.FileMode{0666, 0602, 0664} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if created, err := ensureHistoryCommandLog(path); err != nil || created {
			t.Fatalf("group or world-writable log was not normalized: mode=%o created=%v err=%v", mode, created, err)
		}
		info, _ := os.Lstat(path)
		if err := validHistoryCommandLog(info); err != nil || read(t, path) != "preserved\n" {
			t.Fatalf("normalization changed retained content or left unsafe metadata: %v", err)
		}
	}
	_ = os.Chmod(path, 0644)
	_ = os.Chown(path, 65534, 65534)
	if _, err := ensureHistoryCommandLog(path); err != nil {
		t.Fatalf("non-root log was not reclaimed: %v", err)
	}
	info, _ = os.Lstat(path)
	if err := validHistoryCommandLog(info); err != nil || read(t, path) != "preserved\n" {
		t.Fatalf("reclaimed log metadata or retained content incorrect: %v", err)
	}
	hardLink := filepath.Join(dir, "hard.log")
	if err := os.Link(path, hardLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryCommandLog(path); err == nil {
		t.Fatal("hardlinked log accepted")
	}
	if err := appendHistoryCommand(context.Background(), path, []byte("bad\n")); err == nil {
		t.Fatal("writer accepted a hardlinked log")
	}
	_ = os.Remove(hardLink)
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryCommandLog(link); err == nil {
		t.Fatal("symlink log accepted")
	}
	if err := appendHistoryCommand(context.Background(), link, []byte("bad\n")); err == nil {
		t.Fatal("writer followed log symlink")
	}
	parentLink := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryCommandLog(filepath.Join(parentLink, "other.log")); err == nil {
		t.Fatal("parent symlink accepted")
	}
	unsafeDir := filepath.Join(dir, "unsafe")
	_ = os.Mkdir(unsafeDir, 0777)
	_ = os.Chmod(unsafeDir, 0777)
	if _, err := ensureHistoryCommandLog(filepath.Join(unsafeDir, "other.log")); err == nil {
		t.Fatal("unsafe parent permissions accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHistoryCommandLog(fifo); err == nil {
		t.Fatal("non-regular log accepted")
	}
	// Lock contention honors cancellation rather than blocking the shell.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := appendHistoryCommand(ctx, path, []byte("must not append\n")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait did not honor cancellation: %v", err)
	}
}

func TestHistoryCommandRootStandardLogDirectoryPolicy(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validHistoryCommandLogParent("/var/log", info); err != nil {
		t.Fatalf("standard root logging group rejected: %v", err)
	}
	if err := validHistoryCommandLogParent("/var/log/custom", info); err == nil {
		t.Fatal("trusted-group exception escaped the standard /var/log directory")
	}
	if err := verifyHistoryManagedParents(filepath.Join(dir, "audit.sh")); err == nil {
		t.Fatal("profile script inherited the logging-group exception")
	}
	for _, name := range []string{"syslog", "adm"} {
		group, err := user.LookupGroup(name)
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 0, gid); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Lstat(dir)
		if err := validHistoryCommandLogParent("/var/log", info); err != nil {
			t.Fatalf("standard %s logging group rejected: %v", name, err)
		}
	}
	_ = os.Chown(dir, 0, 65530)
	info, _ = os.Lstat(dir)
	if err := validHistoryCommandLogParent("/var/log", info); err == nil {
		t.Fatal("untrusted logging group accepted")
	}
	_ = os.Chown(dir, 0, 0)
	_ = os.Chmod(dir, 0777)
	info, _ = os.Lstat(dir)
	if err := validHistoryCommandLogParent("/var/log", info); err == nil {
		t.Fatal("public-writable standard log directory accepted")
	}
}

func TestHistoryCommandRootConcurrentAppend(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	path := filepath.Join(dir, "history.log")
	cancel, done := startHistoryCommandTestService(t, dir, path)
	defer stopHistoryCommandTestService(t, cancel, done)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			if err := RequestHistoryCommand(context.Background(), dir, fmt.Sprintf("echo command-%d", i)); err != nil {
				t.Errorf("parallel append: %v", err)
			}
		}(i)
	}
	workers.Wait()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]bool)
	for scanner.Scan() {
		record, err := parseHistoryLine(scanner.Text(), path, "test", 0, time.UTC)
		if err != nil || seen[record.Command] {
			t.Fatalf("corrupt or duplicate append: %+v %v", record, err)
		}
		seen[record.Command] = true
	}
	if err := scanner.Err(); err != nil || len(seen) != 20 {
		t.Fatalf("commands lost: %d %v", len(seen), err)
	}
}

func TestHistoryCommandRootNormalizesDriftAndSeparatesPartialLegacyTail(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	path := filepath.Join(dir, "history.log")
	const retained = "legacy history without a final newline"
	if err := os.WriteFile(path, []byte(retained), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cancel, done := startHistoryCommandTestService(t, dir, path)
	defer stopHistoryCommandTestService(t, cancel, done)
	// A legacy writer may change metadata after initialization. The next root
	// append must enforce the managed metadata again without replacing the inode.
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := RequestHistoryCommand(context.Background(), dir, "printf 'first\\nsecond'"); err != nil {
		t.Fatal(err)
	}
	if err := RequestHistoryCommand(context.Background(), dir, "echo next"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("normalization replaced the retained source inode: %v", err)
	}
	if err := validHistoryCommandLog(after); err != nil {
		t.Fatalf("append did not normalize metadata drift: %v", err)
	}
	data := read(t, path)
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(lines) != 3 || lines[0] != retained {
		t.Fatalf("old bytes were changed or new record joined the partial tail: %q", data)
	}
	for i, command := range []string{"printf 'first\\nsecond'", "echo next"} {
		record, err := parseHistoryLine(lines[i+1], path, "test", 0, time.UTC)
		if err != nil || record.Command != command {
			t.Fatalf("new record is not independently parseable: %+v %v", record, err)
		}
	}
}

func TestHistoryCommandRootPreflight(t *testing.T) {
	dir := historyCommandRootTestDir(t)
	c := Config{History: &HistoryConfig{Enabled: true, Path: filepath.Join(dir, "custom-history.log")}, runtimeDir: dir}
	if err := preflightHistoryCommands(c); err != nil {
		t.Fatalf("fresh socket preflight: %v", err)
	}
	path := HistoryCommandSocket(dir)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("preflight left a socket behind: %v", err)
	}
	if err := os.WriteFile(path, []byte("occupied by administrator"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := preflightHistoryCommands(c); err == nil {
		t.Fatal("occupied socket path accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "occupied by administrator" {
		t.Fatal("preflight modified an occupied path")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "history.log")
	cancel, done := startHistoryCommandTestService(t, dir, logPath)
	defer stopHistoryCommandTestService(t, cancel, done)
	if err := preflightHistoryCommands(c); err == nil {
		t.Fatal("preflight replaced an active command service")
	}
	if err := RequestHistoryCommand(context.Background(), dir, "echo after-preflight"); err != nil {
		t.Fatalf("preflight damaged an active service: %v", err)
	}
}

func TestHistoryCommandDisabledAndTerminal(t *testing.T) {
	for _, history := range []*HistoryConfig{nil, {}, {Enabled: true, Path: "/custom/history.log"}} {
		if err := serveHistoryCommands(context.Background(), Config{History: history}, nil); err != nil {
			t.Fatalf("disabled or nonstandard-runtime history started a writer: %v", err)
		}
	}
	for _, terminal := range []string{"/dev/pts/0", "/dev/pts/12345"} {
		if !validHistoryCommandTerminal(terminal) {
			t.Fatalf("valid terminal rejected: %q", terminal)
		}
	}
	for _, terminal := range []string{"/dev/pts/", "/dev/pts/1] [root", "/tmp/fake", "/dev/pts/1\n", "/dev/pts/../tty"} {
		if validHistoryCommandTerminal(terminal) {
			t.Fatalf("untrusted terminal accepted: %q", terminal)
		}
	}
	if got := historyCommandTerminal(t.TempDir(), 12345); got != "-" {
		t.Fatalf("missing peer metadata did not use placeholder: %q", got)
	}
}
