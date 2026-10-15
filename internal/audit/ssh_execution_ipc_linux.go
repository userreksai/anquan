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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const sshExecutionTimeout = 5 * time.Second

// RequestSSHExecution sends one invocation to the root service without reading
// its configuration or touching installation/state files.
func RequestSSHExecution(parent context.Context, baseDir string, req SSHExecutionRequest) error {
	ctx, cancel := context.WithTimeout(parent, sshExecutionTimeout)
	defer cancel()
	if !filepath.IsAbs(baseDir) {
		return fmt.Errorf("SSH execution base directory must be absolute")
	}
	path := SSHExecutionSocket(baseDir)
	verifyDirectory := verifySSHExecutionDirectory
	if usesSystemRuntimeDirectory(baseDir) {
		verifyDirectory = verifySystemRuntimeDirectory
	}
	if err := verifyDirectory(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %v", ErrSSHExecutionUnavailable, err)
		}
		return err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > sshExecutionFrameLimit {
		return fmt.Errorf("SSH execution request exceeds %d bytes", sshExecutionFrameLimit)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("%w: %v", ErrSSHExecutionUnavailable, err)
		}
		return fmt.Errorf("connect to SSH execution service: %w", err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("SSH execution service is not a Unix socket")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	cred, err := sshExecutionPeerCredentials(unixConn)
	if err != nil {
		return err
	}
	if cred.Uid != 0 {
		return fmt.Errorf("SSH execution service must run as root")
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("send SSH execution request: %w", err)
	}
	responseData, err := readSSHExecutionFrame(conn)
	if err != nil {
		return fmt.Errorf("read SSH execution result: %w", err)
	}
	var response sshExecutionResponse
	if err := decodeSSHExecutionFrame(responseData, &response); err != nil {
		return err
	}
	if response.Version != 1 || response.ID != req.ID {
		return fmt.Errorf("SSH execution service returned a mismatched response")
	}
	if response.Error != "" {
		return fmt.Errorf("SSH execution rejected: %s", response.Error)
	}
	return nil
}

// CurrentSSHExecutionCaller uses the same kernel/process information as IPC.
// It is intended for the root-only fallback when no service accepted a request.
func CurrentSSHExecutionCaller() (SSHExecutionCaller, error) {
	return identifySSHExecutionCaller(uint32(os.Geteuid()), os.Getpid())
}

type sshExecutionReporter func(context.Context, Config, io.Writer, SSHExecutionRequest, SSHExecutionCaller) (LoginRecord, error)

func serveSSHExecutions(ctx context.Context, c Config, writer io.Writer) error {
	return serveSSHExecutionsWithReporter(ctx, c, writer, ReportSSHExecution)
}

func serveSSHExecutionsWithReporter(parent context.Context, c Config, writer io.Writer, report sshExecutionReporter) error {
	listener, socketInfo, err := listenSSHExecutions(c.runtimeDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	connections := make(map[*net.UnixConn]struct{})
	var handlers sync.WaitGroup
	slots := make(chan struct{}, 32)
	closeConnections := func() {
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		closeConnections()
	})
	defer func() {
		cancel()
		_ = listener.Close()
		closeConnections()
		handlers.Wait()
		stop()
		removeOwnSSHExecutionSocket(listener.Addr().String(), socketInfo)
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept SSH execution request: %w", err)
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
		connections[conn] = struct{}{}
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
			handleSSHExecution(ctx, c, writer, conn, report)
		}()
	}
}

func handleSSHExecution(parent context.Context, c Config, writer io.Writer, conn *net.UnixConn, report sshExecutionReporter) {
	ctx, cancel := context.WithTimeout(parent, sshExecutionTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	response := sshExecutionResponse{Version: 1}
	finish := func(err error) {
		if err != nil {
			response.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(response)
	}
	data, err := readSSHExecutionFrame(conn)
	if err != nil {
		finish(err)
		return
	}
	var req SSHExecutionRequest
	if err := decodeSSHExecutionFrame(data, &req); err != nil {
		finish(err)
		return
	}
	response.ID = req.ID
	cred, err := sshExecutionPeerCredentials(conn)
	if err != nil {
		finish(err)
		return
	}
	caller, err := identifySSHExecutionCaller(cred.Uid, int(cred.Pid))
	if err != nil {
		finish(err)
		return
	}
	if err := ctx.Err(); err != nil {
		finish(err)
		return
	}
	_, err = report(ctx, c, writer, req, caller)
	if err != nil && parent.Err() == nil && c.location != nil {
		_ = writeLog(c, writer, time.Now(), "ssh_execution_error", map[string]any{
			"id": req.ID, "caller_uid": caller.UID, "caller_pid": caller.PID, "error": err.Error(),
		})
	}
	finish(err)
}

func readSSHExecutionFrame(reader io.Reader) ([]byte, error) {
	data, err := bufio.NewReader(io.LimitReader(reader, sshExecutionFrameLimit+1)).ReadBytes('\n')
	if len(data) > sshExecutionFrameLimit {
		return nil, fmt.Errorf("SSH execution request exceeds %d bytes", sshExecutionFrameLimit)
	}
	if err != nil {
		return nil, fmt.Errorf("incomplete SSH execution message: %w", err)
	}
	return data, nil
}

func sshExecutionPeerCredentials(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if credentialErr != nil {
		return nil, fmt.Errorf("read SSH execution peer credentials: %w", credentialErr)
	}
	return cred, nil
}

func identifySSHExecutionCaller(uid uint32, pid int) (SSHExecutionCaller, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return SSHExecutionCaller{}, fmt.Errorf("identify SSH execution account: %w", err)
	}
	pids, err := sshExecutionAncestors("/proc", pid)
	if err != nil {
		return SSHExecutionCaller{}, err
	}
	return SSHExecutionCaller{UID: uid, PID: pid, Username: account.Username, SSHDPIDs: pids}, nil
}

// A process name alone is user-controlled. Only root-owned, non-writable sshd
// executables count as ancestors for the trusted journal lookup.
func sshExecutionAncestors(procDir string, pid int) ([]int, error) {
	var ancestors []int
	seen := make(map[int]bool)
	for depth := 0; pid > 0 && depth < 64; depth++ {
		if seen[pid] {
			return nil, fmt.Errorf("SSH execution process ancestry contains a loop")
		}
		seen[pid] = true
		dir := filepath.Join(procDir, strconv.Itoa(pid))
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			return nil, fmt.Errorf("inspect SSH execution process %d: %w", pid, err)
		}
		end := strings.LastIndex(string(stat), ")")
		if end < 0 {
			return nil, fmt.Errorf("invalid SSH execution process metadata")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid SSH execution process parent")
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent < 0 {
			return nil, fmt.Errorf("invalid SSH execution process parent")
		}
		name, err := os.Readlink(filepath.Join(dir, "exe"))
		if err == nil && (filepath.Base(name) == "sshd" || filepath.Base(name) == "sshd-session") {
			info, err := os.Stat(filepath.Join(dir, "exe"))
			if err == nil && sshExecutionRootOwned(info) && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 {
				ancestors = append(ancestors, pid)
			}
		}
		pid = parent
	}
	return ancestors, nil
}

func verifySSHExecutionDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect SSH execution directory: %w", err)
	}
	if !info.IsDir() || !sshExecutionRootOwned(info) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("SSH execution directory must be a root-owned directory not writable by other users: %s", path)
	}
	return nil
}

func sshExecutionRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func listenSSHExecutions(baseDir string) (*net.UnixListener, os.FileInfo, error) {
	if os.Geteuid() != 0 {
		return nil, nil, fmt.Errorf("SSH execution service requires root")
	}
	if !filepath.IsAbs(baseDir) {
		return nil, nil, fmt.Errorf("SSH execution base directory must be absolute")
	}
	if err := verifySSHExecutionDirectory(baseDir); err != nil {
		return nil, nil, err
	}
	path := SSHExecutionSocket(baseDir)
	dir := filepath.Dir(path)
	if usesSystemRuntimeDirectory(baseDir) {
		if err := prepareSystemRuntimeDirectory(dir, 0755); err != nil {
			return nil, nil, err
		}
	} else {
		if err := ensureRootRuntimeDirectory(dir, 0755); err != nil {
			return nil, nil, err
		}
	}
	if err := clearStaleSSHExecutionSocket(path); err != nil {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("listen for SSH executions: %w", err)
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

func clearStaleSSHExecutionSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || !sshExecutionRootOwned(info) {
		return fmt.Errorf("SSH execution socket path is occupied by another file")
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("SSH execution socket already has an active listener")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot determine whether SSH execution socket is stale: %w", err)
	}
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) || current.Mode()&os.ModeSocket == 0 || !sshExecutionRootOwned(current) {
		return fmt.Errorf("SSH execution socket changed during stale socket check")
	}
	return os.Remove(path)
}

func removeOwnSSHExecutionSocket(path string, original os.FileInfo) {
	current, err := os.Lstat(path)
	if err == nil && current.Mode()&os.ModeSocket != 0 && sshExecutionRootOwned(current) && os.SameFile(original, current) {
		_ = os.Remove(path)
	}
}
