//go:build linux

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const historyCommandTimeout = 2 * time.Second

// RequestHistoryCommand never reads the service's root-only configuration and
// never falls back to local writes or installation when the service is absent.
func RequestHistoryCommand(parent context.Context, baseDir, command string) error {
	if err := validateHistoryCommand(command); err != nil {
		return err
	}
	if !filepath.IsAbs(baseDir) {
		return fmt.Errorf("command service base directory must be absolute")
	}
	path := HistoryCommandSocket(baseDir)
	verify := verifySSHExecutionDirectory
	if usesSystemRuntimeDirectory(baseDir) {
		verify = verifySystemRuntimeDirectory
	}
	if err := verify(filepath.Dir(path)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, historyCommandTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("connect to command service: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	cred, err := sshExecutionPeerCredentials(conn.(*net.UnixConn))
	if err != nil || cred.Uid != 0 {
		return fmt.Errorf("command service must have a verified root peer: %v", err)
	}
	if err := json.NewEncoder(conn).Encode(historyCommandRequest{Command: command}); err != nil {
		return fmt.Errorf("send command: %w", err)
	}
	data, err := readHistoryCommandFrame(conn)
	if err != nil {
		return err
	}
	var response historyCommandResponse
	if err := decodeHistoryCommandFrame(data, &response); err != nil {
		return err
	}
	if response.Version != 1 {
		return fmt.Errorf("command service returned an unsupported response")
	}
	if response.Error != "" {
		return fmt.Errorf("command recording rejected: %s", response.Error)
	}
	return nil
}

func serveHistoryCommands(ctx context.Context, c Config, writer io.Writer) error {
	if filepath.Clean(c.runtimeDir) != filepath.Dir(historyCommandBinaryPath) || c.History == nil || !c.History.Enabled || !isManagedHistoryScript(historyAuditScriptPath) {
		return nil
	}
	return serveHistoryCommandsAt(ctx, c.runtimeDir, c.History.Path, c.History.location, func() error {
		return writeLog(c, writer, time.Now(), "history_command_ready", map[string]string{
			"socket": HistoryCommandSocket(c.runtimeDir), "path": c.History.Path,
		})
	})
}

// Configuration activation runs this after joining the previous workers. A
// real bind detects occupied paths and permission errors before acknowledging
// installation; it leaves no socket behind for the actual worker to replace.
func preflightHistoryCommands(c Config) error {
	if c.History == nil || !c.History.Enabled {
		return nil
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(c.runtimeDir) {
		return fmt.Errorf("command recording preflight requires root and an absolute runtime directory")
	}
	listener, info, err := listenHistoryCommands(c.runtimeDir)
	if err != nil {
		return fmt.Errorf("command recording socket preflight: %w", err)
	}
	path := listener.Addr().String()
	err = listener.Close()
	removeOwnSSHExecutionSocket(path, info)
	return err
}

func serveHistoryCommandsAt(parent context.Context, baseDir, logPath string, location *time.Location, ready ...func() error) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("command recording service requires root")
	}
	if !filepath.IsAbs(baseDir) || location == nil {
		return fmt.Errorf("command recording service requires an absolute base and configured timezone")
	}
	if _, err := ensureHistoryCommandLog(logPath); err != nil {
		return err
	}
	listener, socketInfo, err := listenHistoryCommands(baseDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	connections := make(map[*net.UnixConn]bool)
	var handlers sync.WaitGroup
	slots := make(chan struct{}, 32)
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	})
	defer func() {
		cancel()
		_ = listener.Close()
		handlers.Wait()
		stop()
		removeOwnSSHExecutionSocket(listener.Addr().String(), socketInfo)
	}()
	for _, notify := range ready {
		if err := notify(); err != nil {
			return err
		}
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept command recording request: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			<-slots
			return nil
		}
		connections[conn] = true
		mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() {
				_ = conn.Close()
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
				<-slots
			}()
			handleHistoryCommand(ctx, conn, logPath, location)
		}()
	}
}

func handleHistoryCommand(parent context.Context, conn *net.UnixConn, logPath string, location *time.Location) {
	ctx, cancel := context.WithTimeout(parent, historyCommandTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	response := historyCommandResponse{Version: 1}
	finish := func(err error) {
		if err != nil {
			response.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(response)
	}
	data, err := readHistoryCommandFrame(conn)
	if err != nil {
		finish(err)
		return
	}
	var req historyCommandRequest
	if err := decodeHistoryCommandFrame(data, &req); err != nil {
		finish(err)
		return
	}
	if err := validateHistoryCommand(req.Command); err != nil {
		finish(err)
		return
	}
	cred, err := sshExecutionPeerCredentials(conn)
	if err != nil {
		finish(err)
		return
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(cred.Uid), 10))
	if err != nil || !utf8.ValidString(account.Username) || strings.ContainsAny(account.Username, "]\r\n\x00") || account.Username == "" || len(account.Username) > 256 {
		finish(fmt.Errorf("command peer has no valid operating system account"))
		return
	}
	terminal := historyCommandTerminal("/proc", int(cred.Pid))
	line := fmt.Sprintf("[%s] [%s] [%s] [%s]\n", time.Now().In(location).Format("2006-01-02 15:04:05"), account.Username, terminal, escapedHistoryCommand(req.Command))
	finish(appendHistoryCommand(ctx, logPath, []byte(line)))
}

func listenHistoryCommands(baseDir string) (*net.UnixListener, os.FileInfo, error) {
	if err := verifySSHExecutionDirectory(baseDir); err != nil {
		return nil, nil, err
	}
	path := HistoryCommandSocket(baseDir)
	dir := filepath.Dir(path)
	if usesSystemRuntimeDirectory(baseDir) {
		if err := prepareSystemRuntimeDirectory(dir, 0755); err != nil {
			return nil, nil, err
		}
	} else if err := ensureRootRuntimeDirectory(dir, 0755); err != nil {
		return nil, nil, err
	}
	if err := clearStaleSSHExecutionSocket(path); err != nil {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	listener.SetUnlinkOnClose(false)
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	if err := os.Chmod(path, 0666); err != nil {
		_ = listener.Close()
		removeOwnSSHExecutionSocket(path, info)
		return nil, nil, err
	}
	return listener, info, nil
}

func verifyHistoryManagedParents(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("command log path must be absolute")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if err := verifySSHExecutionDirectory(parent); err != nil {
			return err
		}
		if next := filepath.Dir(parent); next == parent {
			return nil
		}
	}
}

func verifyHistoryManagedOwner(info os.FileInfo) bool { return sshExecutionRootOwned(info) }

// Ubuntu may permit its trusted logging group to manage /var/log. This narrow
// exception applies only to that standard directory, never profile.d or custom
// ancestors. Every opened log is independently checked and never followed.
func verifyHistoryCommandLogParents(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("command log path must be absolute")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if err := validHistoryCommandLogParent(parent, info); err != nil {
			return err
		}
		if next := filepath.Dir(parent); next == parent {
			return nil
		}
	}
}

func validHistoryCommandLogParent(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !sshExecutionRootOwned(info) || info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("command log parent must be a root-owned directory not writable by everyone: %s", path)
	}
	if info.Mode().Perm()&0020 == 0 {
		return nil
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if path == "/var/log" && ok {
		if owner.Gid == 0 {
			return nil
		}
		for _, name := range []string{"syslog", "adm"} {
			group, err := user.LookupGroup(name)
			if err == nil && group.Gid == strconv.FormatUint(uint64(owner.Gid), 10) {
				return nil
			}
		}
	}
	return fmt.Errorf("command log parent is writable by an untrusted group: %s", path)
}

func validHistoryCommandLog(info os.FileInfo) error {
	if err := validHistoryCommandLogInode(info); err != nil {
		return err
	}
	owner := info.Sys().(*syscall.Stat_t)
	if owner.Uid != 0 || owner.Gid != 0 || info.Mode().Perm() != 0644 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("command log must be owned by root:root with mode 0644")
	}
	return nil
}

func validHistoryCommandLogInode(info os.FileInfo) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || owner.Nlink != 1 {
		return fmt.Errorf("command log must be a regular file with one link")
	}
	return nil
}

func ensureHistoryCommandLog(path string) (bool, error) {
	if os.Geteuid() != 0 {
		return false, fmt.Errorf("managing the command log requires root")
	}
	if err := verifyHistoryCommandLogParents(path); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	created := false
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if err == nil {
		if err := validHistoryCommandLogInode(info); err != nil {
			return false, err
		}
	} else if os.IsNotExist(err) {
		flags |= unix.O_CREAT | unix.O_EXCL
		created = true
	} else {
		return false, err
	}
	fd, err := unix.Open(path, flags, 0644)
	if err == unix.EEXIST {
		return ensureHistoryCommandLog(path)
	}
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), historyCommandTimeout)
	defer cancel()
	if err := lockHistoryCommandLog(ctx, fd); err != nil {
		return created, err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := normalizeHistoryCommandLog(f, path); err != nil {
		return created, err
	}
	return created, f.Sync()
}

func appendHistoryCommand(ctx context.Context, path string, line []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyHistoryCommandLogParents(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open command log: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err := lockHistoryCommandLog(ctx, fd); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := normalizeHistoryCommandLog(f, path); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, err := f.ReadAt(tail[:], info.Size()-1); err != nil {
			return err
		}
		if tail[0] != '\n' {
			// Preserve a retained partial legacy record and start the new one on
			// its own physical line. Both bytes are appended under the same lock.
			line = append([]byte{'\n'}, line...)
		}
	}
	written, err := f.Write(line)
	if err == nil && written != len(line) {
		return io.ErrShortWrite
	}
	return err
}

func lockHistoryCommandLog(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Only metadata of the verified opened inode is changed. The file's retained
// bytes and identity stay intact, so an existing collector cursor remains valid.
func normalizeHistoryCommandLog(f *os.File, path string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("managing the command log requires root")
	}
	if err := verifyHistoryCommandLogParents(path); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := validHistoryCommandLogInode(info); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return fmt.Errorf("command log changed before normalization")
	}
	if err := validHistoryCommandLogInode(current); err != nil {
		return err
	}
	owner := info.Sys().(*syscall.Stat_t)
	if owner.Uid != 0 || owner.Gid != 0 {
		if err := f.Chown(0, 0); err != nil {
			return fmt.Errorf("set command log owner: %w", err)
		}
	}
	if info.Mode().Perm() != 0644 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		if err := f.Chmod(0644); err != nil {
			return fmt.Errorf("set command log permissions: %w", err)
		}
	}
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if err := validHistoryCommandLog(info); err != nil {
		return err
	}
	current, err = os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return fmt.Errorf("command log changed during normalization")
	}
	return validHistoryCommandLog(current)
}

// fd 2 normally belongs to the recording child, or to its interactive parent
// when the hook redirects helper errors. Client-supplied terminal text is never
// accepted. Missing metadata (including a process that has exited) is harmless.
func historyCommandTerminal(procDir string, pid int) string {
	seen := make(map[int]bool)
	for depth := 0; pid > 0 && depth < 16 && !seen[pid]; depth++ {
		seen[pid] = true
		dir := filepath.Join(procDir, strconv.Itoa(pid))
		if terminal, err := os.Readlink(filepath.Join(dir, "fd", "2")); err == nil && validHistoryCommandTerminal(terminal) {
			return terminal
		}
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			break
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			break
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 2 {
			break
		}
		pid, err = strconv.Atoi(fields[1])
		if err != nil {
			break
		}
	}
	return "-"
}

func validHistoryCommandTerminal(path string) bool {
	if !strings.HasPrefix(path, "/dev/pts/") {
		return false
	}
	number := strings.TrimPrefix(path, "/dev/pts/")
	if number == "" {
		return false
	}
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
