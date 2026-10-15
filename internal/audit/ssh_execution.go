package audit

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// An execution ID identifies this invocation, independently of the original
// authentication record. Reusing a request preserves its UDP event identity.
type SSHExecutionRequest struct {
	ID         string `json:"id"`
	Connection string `json:"connection"`
}

// The root IPC server derives this identity from the peer process, never from
// client-supplied JSON. Root callers may report the authentication before sudo.
type SSHExecutionCaller struct {
	UID      uint32
	PID      int
	Username string
	SSHDPIDs []int
}

type sshExecutionConnection struct {
	clientIP   net.IP
	clientPort int
	serverIP   net.IP
	serverPort int
}

func parseSSHExecutionConnection(value string) (*sshExecutionConnection, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return nil, errors.New("SSH_CONNECTION must contain client IP, client port, server IP and server port")
	}
	connection := &sshExecutionConnection{clientIP: net.ParseIP(fields[0]), serverIP: net.ParseIP(fields[2])}
	if connection.clientIP == nil || connection.serverIP == nil || connection.clientIP.IsUnspecified() || connection.serverIP.IsUnspecified() {
		return nil, errors.New("SSH_CONNECTION contains an invalid IP address")
	}
	for i, target := range map[int]*int{1: &connection.clientPort, 3: &connection.serverPort} {
		port, err := strconv.Atoi(fields[i])
		if err != nil || port < 1 || port > 65535 || strings.IndexFunc(fields[i], func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, errors.New("SSH_CONNECTION contains an invalid port")
		}
		*target = port
	}
	return connection, nil
}

func NewSSHExecutionRequest(connection string) (SSHExecutionRequest, error) {
	parsed, err := parseSSHExecutionConnection(connection)
	if err != nil {
		return SSHExecutionRequest{}, err
	}
	if parsed == nil {
		connection = ""
	} else {
		connection = fmt.Sprintf("%s %d %s %d", parsed.clientIP, parsed.clientPort, parsed.serverIP, parsed.serverPort)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return SSHExecutionRequest{}, fmt.Errorf("create SSH execution identity: %w", err)
	}
	return SSHExecutionRequest{ID: hex.EncodeToString(id[:]), Connection: connection}, nil
}

// ReportSSHExecution immediately reports a real source record for this
// invocation. It neither consumes the incremental .logins cursor nor runs the
// file/process scan, so repeated executions can report one authentication.
func ReportSSHExecution(parent context.Context, c Config, writer io.Writer, req SSHExecutionRequest, caller SSHExecutionCaller) (LoginRecord, error) {
	var record LoginRecord
	if c.waitingForConfig || c.location == nil {
		return record, errors.New("SSH execution has no valid audit configuration")
	}
	if !c.Login.Enabled {
		return record, errors.New("SSH login reporting is disabled by configuration")
	}
	if c.Login.Mode == "poll" {
		return record, errors.New("SSH login configuration uses poll mode; execution reporting is disabled")
	}
	if len(c.Server) == 0 {
		return record, errors.New("SSH execution reporting has no UDP server configured")
	}
	id, err := hex.DecodeString(req.ID)
	if err != nil || len(req.ID) != 32 || len(id) != 16 || req.ID != strings.ToLower(req.ID) {
		return record, errors.New("invalid SSH execution identity")
	}
	connection, err := parseSSHExecutionConnection(req.Connection)
	if err != nil {
		return record, err
	}
	if caller.UID != 0 && (connection == nil || strings.TrimSpace(caller.Username) == "") {
		return record, errors.New("non-root SSH execution requires a verified caller and SSH connection")
	}
	if c.Login.TimeoutSeconds <= 0 {
		c.Login.TimeoutSeconds = 10
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.Login.TimeoutSeconds)*time.Second)
	defer cancel()
	invokedAt := time.Now().In(c.location)
	var source *LoginRecord
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return record, err
		}
		source, err = findSSHExecutionRecord(ctx, c.Login, connection, caller)
		if err != nil {
			return record, err
		}
		if source != nil {
			break
		}
		if attempt < 3 {
			// Accepted may still be queued for journald when sshrc first runs.
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return record, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if source == nil {
		return record, errors.New("no successful SSH authentication matches this execution in the configured source")
	}
	record = *source
	record.SourceRecordID = source.ID
	if record.SourceRecordID == "" {
		body, err := json.Marshal(source)
		if err != nil {
			return LoginRecord{}, err
		}
		record.SourceRecordID = loginDigest(string(body))
	}
	record.ID, record.Trigger, record.InvokedAt = req.ID, "execution", &invokedAt
	record.ExecutedBy = caller.Username
	if record.ExecutedBy == "" {
		record.ExecutedBy = strconv.FormatUint(uint64(caller.UID), 10)
	}
	record.LoginTime = record.LoginTime.In(c.location)
	if err := ctx.Err(); err != nil {
		return record, err
	}
	if err := writeLog(c, writer, invokedAt, "ssh_login", record); err != nil {
		return record, err
	}
	host, err := os.Hostname()
	if err != nil {
		return record, err
	}
	notifications := notifySSHLogins(ctx, c, host, []LoginRecord{record})
	logErr := writeLog(c, writer, time.Now(), "ssh_execution_complete", struct {
		ID             string               `json:"id"`
		SourceRecordID string               `json:"source_record_id"`
		CallerUID      uint32               `json:"caller_uid"`
		CallerPID      int                  `json:"caller_pid"`
		Notifications  []NotificationResult `json:"notifications"`
	}{record.ID, record.SourceRecordID, caller.UID, caller.PID, notifications})
	failures := []error{logErr}
	for _, notification := range notifications {
		if notification.Error != "" {
			failures = append(failures, fmt.Errorf("%s: %s", notification.Server, notification.Error))
		}
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	}
	return record, errors.Join(failures...)
}

func sshExecutionMatches(record LoginRecord, connection *sshExecutionConnection, caller SSHExecutionCaller, legacyPort bool) bool {
	if record.LoginTime.IsZero() || (caller.UID != 0 && record.User != caller.Username) {
		return false
	}
	if connection == nil {
		return caller.UID == 0
	}
	if ip := net.ParseIP(record.SourceIP); ip == nil || !ip.Equal(connection.clientIP) {
		return false
	}
	return record.SourcePort == connection.clientPort || (legacyPort && record.SourcePort == 0)
}

func findSSHExecutionRecord(ctx context.Context, c LoginConfig, connection *sshExecutionConnection, caller SSHExecutionCaller) (*LoginRecord, error) {
	if c.Source == "journal" {
		return readSSHExecutionJournal(ctx, c, connection, caller)
	}
	if c.Source == "authlog" {
		return readSSHExecutionAuthLog(ctx, c, connection, caller)
	}
	var records []LoginRecord
	var err error
	switch c.Source {
	case "jsonl":
		var file *os.File
		file, err = openSSHExecutionFile(c.Path)
		if err == nil {
			records, err = parseJSONLRecords(sshExecutionContextReader{ctx, file})
			file.Close()
		}
	case "wtmp":
		records, err = readAllWtmpContext(ctx, c)
	default:
		err = fmt.Errorf("unsupported SSH execution source %q", c.Source)
	}
	if err != nil {
		return nil, err
	}
	var selected *LoginRecord
	for _, record := range records {
		if sshExecutionMatches(record, connection, caller, true) && (selected == nil || !record.LoginTime.Before(selected.LoginTime)) {
			copy := record
			selected = &copy
		}
	}
	return selected, ctx.Err()
}

func sshExecutionJournalArgs(caller SSHExecutionCaller) []string {
	args := []string{"--boot=0", "--reverse", "--no-pager", "--quiet", "--output=json", "--lines=2000"}
	seen := map[int]bool{}
	for _, pid := range caller.SSHDPIDs {
		if pid > 0 && !seen[pid] {
			args = append(args, "_PID="+strconv.Itoa(pid))
			seen[pid] = true
		}
	}
	if len(seen) == 0 {
		args = append(args, "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd-session")
	}
	return args
}

func readSSHExecutionJournal(ctx context.Context, c LoginConfig, connection *sshExecutionConnection, caller SSHExecutionCaller) (*LoginRecord, error) {
	command := c.JournalCommand
	if command == "" {
		command = "journalctl"
	}
	cmd := exec.CommandContext(ctx, command, sshExecutionJournalArgs(caller)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	stderr := &cappedBuffer{max: 64 * 1024}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start SSH execution journal query: %w", err)
	}
	var selected *LoginRecord
	var parseErr error
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		count++
		var entry journalLoginEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			parseErr = fmt.Errorf("parse SSH execution journal JSON: %w", err)
			break
		}
		if acceptedSSH.MatchString(entry.Message) {
			micros, err := strconv.ParseInt(entry.Timestamp, 10, 64)
			if err != nil || entry.Cursor == "" {
				parseErr = errors.New("SSH execution journal authentication has no valid timestamp or cursor")
				break
			}
			record, err := parseAcceptedSSH(entry.Message, time.UnixMicro(micros), entry.Cursor)
			if err != nil {
				parseErr = err
				break
			}
			if record != nil && sshExecutionMatches(*record, connection, caller, false) {
				selected = record
				break // --reverse returns the most recent matching authentication.
			}
		}
		if count >= 2000 {
			break
		}
	}
	if parseErr == nil {
		parseErr = scanner.Err()
	}
	stoppedEarly := selected != nil || parseErr != nil || count >= 2000
	if stoppedEarly {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil && !stoppedEarly {
		return nil, fmt.Errorf("SSH execution journal query failed: %w; %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return nil, fmt.Errorf("SSH execution journal query warning: %s", strings.TrimSpace(stderr.String()))
	}
	return selected, nil
}

type sshExecutionContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r sshExecutionContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func openSSHExecutionFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32*1024*1024 {
		return nil, errors.New("SSH execution JSONL source must be a regular file at most 32 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32*1024*1024 {
		file.Close()
		return nil, errors.New("SSH execution JSONL source must be a regular file at most 32 MiB")
	}
	return file, nil
}

func readSSHExecutionAuthLog(ctx context.Context, c LoginConfig, connection *sshExecutionConnection, caller SSHExecutionCaller) (*LoginRecord, error) {
	files, err := authLogFiles(c.Path)
	if err != nil {
		return nil, err
	}
	var selected *LoginRecord
	for i := len(files) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, err := readSSHExecutionAuthFile(ctx, files[i].path, connection, caller)
		if err != nil {
			return nil, err
		}
		if record != nil && (selected == nil || !record.LoginTime.Before(selected.LoginTime)) {
			selected = record
		}
	}
	return selected, nil
}

func readSSHExecutionAuthFile(ctx context.Context, path string, connection *sshExecutionConnection, caller SSHExecutionCaller) (*LoginRecord, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SSH execution authentication source must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SSH execution authentication source must be a regular file")
	}
	prefix, err := authPrefix(file, int(min(info.Size(), 256)))
	if err != nil {
		return nil, err
	}
	// Keep execution work bounded even on hosts retaining very large auth logs.
	offset := max(int64(0), info.Size()-8*1024*1024)
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(sshExecutionContextReader{ctx, file}, 64*1024)
	if offset > 0 {
		partial, err := readAuthLine(reader)
		if err != nil && err != io.EOF {
			return nil, err
		}
		offset += int64(len(partial))
	}
	var selected *LoginRecord
	for {
		line, err := readAuthLine(reader)
		if err == io.EOF {
			break // An incomplete authentication line is retried after it is flushed.
		}
		if err != nil {
			return nil, err
		}
		id := loginDigest(prefix + ":" + strconv.FormatInt(offset, 10) + ":" + line)
		record, err := parseAuthLine(line, time.Now(), id)
		if err != nil {
			return nil, err
		}
		if record != nil && sshExecutionMatches(*record, connection, caller, false) && (selected == nil || !record.LoginTime.Before(selected.LoginTime)) {
			selected = record
		}
		offset += int64(len(line))
	}
	return selected, ctx.Err()
}
