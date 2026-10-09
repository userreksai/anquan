package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The returned baseline is committed by the caller only after the report is
// durably published. A failed collection never advances its durable cursor.
type loginBaseline struct {
	Version       int            `json:"version"`
	SourceKey     string         `json:"source_key"`
	Since         time.Time      `json:"since"`
	JournalCursor string         `json:"journal_cursor,omitempty"`
	Auth          *authLogCursor `json:"auth,omitempty"`
	Seen          map[string]int `json:"seen,omitempty"`
	Latest        *LoginRecord   `json:"latest,omitempty"`
}

type authLogCursor struct {
	Identity    string `json:"identity,omitempty"`
	Prefix      string `json:"prefix"`
	PrefixBytes int    `json:"prefix_bytes"`
	Offset      int64  `json:"offset"`
}

func collectSSHLogins(c Config, now time.Time) (LoginResult, *loginBaseline, []Issue) {
	lc := c.Login
	r := LoginResult{Enabled: lc.Enabled, Success: true, Source: lc.Source, Path: lc.Path, Records: []LoginRecord{}}
	if !lc.Enabled {
		return r, nil, nil
	}
	if lc.MaxRecords <= 0 {
		lc.MaxRecords = 1000
	}
	if lc.TimeoutSeconds <= 0 {
		lc.TimeoutSeconds = 10
	}
	if lc.InitialLookbackHours <= 0 {
		lc.InitialLookbackHours = 24
	}
	if lc.JournalCommand == "" {
		lc.JournalCommand = "journalctl"
	}
	if lc.LastCommand == "" {
		lc.LastCommand = "last"
	}
	key := loginDigest(lc.Source + "\x00" + lc.Path)
	s := &loginBaseline{Version: 1, SourceKey: key, Since: now.Add(-time.Duration(lc.InitialLookbackHours) * time.Hour), Seen: map[string]int{}}
	err := readState(c.StateFile+".logins", "login", s)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return loginFailure(r, fmt.Errorf("read SSH login state: %w", err))
	}
	if err == nil && (s.Version != 1 || s.SourceKey != key || s.Since.IsZero()) {
		return loginFailure(r, fmt.Errorf("SSH login state source/version changed; archive %s.logins before changing login source", c.StateFile))
	}
	if s.Auth != nil && (s.Auth.Offset < 0 || s.Auth.PrefixBytes < 0 || s.Auth.PrefixBytes > 256 || (s.Auth.PrefixBytes == 0 && s.Auth.Offset != 0) || (s.Auth.PrefixBytes > 0 && len(s.Auth.Prefix) != 64)) {
		return loginFailure(r, fmt.Errorf("invalid SSH auth log cursor in %s.logins", c.StateFile))
	}
	for _, count := range s.Seen {
		if count < 1 {
			return loginFailure(r, fmt.Errorf("invalid SSH deduplication state in %s.logins", c.StateFile))
		}
	}
	if s.Seen == nil {
		s.Seen = map[string]int{}
	}
	r.Record = s.Latest
	switch lc.Source {
	case "journal":
		r.Records, r.Pending, err = readJournalLogins(lc, s)
	case "authlog":
		r.Records, r.Pending, err = readAuthLogins(lc, s, now)
	case "jsonl", "wtmp":
		var records []LoginRecord
		if lc.Source == "jsonl" {
			var f *os.File
			f, err = os.Open(lc.Path)
			if err == nil {
				records, err = parseJSONLRecords(f)
				f.Close()
			}
		} else {
			records, err = readAllWtmp(lc)
		}
		if err == nil {
			r.Records, r.Pending = unseenLogins(records, lc.MaxRecords, s, lc.Source == "wtmp")
		}
	default:
		err = fmt.Errorf("unsupported SSH login source %q", lc.Source)
	}
	if err != nil {
		return loginFailure(r, err)
	}
	if r.Records == nil {
		r.Records = []LoginRecord{}
	}
	location := c.location
	if location == nil {
		location = time.UTC
	}
	for i := range r.Records {
		r.Records[i].LoginTime = r.Records[i].LoginTime.In(location)
	}
	latest := latestLogin(r.Records)
	if latest != nil && (s.Latest == nil || !latest.LoginTime.Before(s.Latest.LoginTime)) {
		s.Latest = latest
	}
	if s.Latest != nil {
		copy := *s.Latest
		copy.LoginTime = copy.LoginTime.In(location)
		r.Record = &copy
	}
	return r, s, nil
}

func loginFailure(r LoginResult, err error) (LoginResult, *loginBaseline, []Issue) {
	r.Success = false
	r.Records = []LoginRecord{}
	r.Pending = false
	return r, nil, []Issue{{Module: "login", Message: err.Error()}}
}

func loginDigest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func unseenLogins(records []LoginRecord, limit int, s *loginBaseline, boundedHistory bool) ([]LoginRecord, bool) {
	// Stable ordering and occurrence counts retain distinct identical records,
	// including two logins with the same timestamp, user and source address.
	sort.SliceStable(records, func(i, j int) bool { return records[i].LoginTime.Before(records[j].LoginTime) })
	counts := map[string]int{}
	var out []LoginRecord
	for _, record := range records {
		if boundedHistory && record.LoginTime.Before(s.Since) {
			continue
		}
		b, _ := json.Marshal(record)
		key := loginDigest(string(b))
		counts[key]++
		if counts[key] <= s.Seen[key] {
			continue
		}
		if len(out) >= limit {
			return out, true
		}
		s.Seen[key] = counts[key]
		if record.ID == "" {
			record.ID = key + ":" + strconv.Itoa(counts[key])
		}
		out = append(out, record)
	}
	return out, false
}

// Unlike the legacy latest-login adapter, this reads the complete retained
// wtmp. The output cap fails explicitly instead of discarding older records.
func readAllWtmp(c LoginConfig) ([]LoginRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.LastCommand, "-w", "-i", "--time-format", "iso", "-f", c.Path)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	stdout, stderr := &cappedBuffer{max: 32 * 1024 * 1024}, &cappedBuffer{max: 64 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read wtmp (last): %w; %s", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return nil, fmt.Errorf("last reported a warning: %s", strings.TrimSpace(stderr.String()))
	}
	return parseLastRecords(stdout.String())
}

type journalLoginEntry struct {
	Cursor    string `json:"__CURSOR"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
	Message   string `json:"MESSAGE"`
}

func journalArgs(c LoginConfig, s *loginBaseline) []string {
	args := []string{"--no-pager", "--quiet", "--output=json"}
	if s.JournalCursor != "" {
		args = append(args, "--after-cursor="+s.JournalCursor)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(s.Since.Unix(), 10))
	}
	// Field disjunction covers distributions using ssh.service, sshd.service,
	// and newer OpenSSH installations with the sshd-session process.
	return append(args, "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd-session")
}

func readJournalLogins(c LoginConfig, s *loginBaseline) ([]LoginRecord, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.JournalCommand, journalArgs(c, s)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	stderr := &cappedBuffer{max: 64 * 1024}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("start journalctl: %w", err)
	}
	records, pending, parseErr := parseJournalPage(stdout, c.MaxRecords, s)
	if pending || parseErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, false, parseErr
	}
	if ctx.Err() != nil {
		return nil, false, fmt.Errorf("journalctl timed out after %d seconds", c.TimeoutSeconds)
	}
	if waitErr != nil && !pending {
		return nil, false, fmt.Errorf("journalctl failed: %w; %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return nil, false, fmt.Errorf("journalctl reported a warning: %s", strings.TrimSpace(stderr.String()))
	}
	return records, pending, nil
}

func parseJournalPage(reader io.Reader, limit int, s *loginBaseline) ([]LoginRecord, bool, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var records []LoginRecord
	processed := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var entry journalLoginEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, false, fmt.Errorf("parse journal JSON: %w", err)
		}
		if entry.Cursor == "" {
			return nil, false, fmt.Errorf("journal entry has no cursor")
		}
		micros, err := strconv.ParseInt(entry.Timestamp, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("invalid journal realtime timestamp %q", entry.Timestamp)
		}
		record, err := parseAcceptedSSH(entry.Message, time.UnixMicro(micros), entry.Cursor)
		if err != nil {
			return nil, false, err
		}
		if record != nil {
			records = append(records, *record)
		}
		s.JournalCursor = entry.Cursor
		processed++
		// Stop before reading a further event: only this processed page is
		// committed, and --after-cursor resumes at the very next event.
		if processed >= limit {
			return records, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("read journal: %w", err)
	}
	return records, false, nil
}

var acceptedSSH = regexp.MustCompile(`\bAccepted (\S+) for (\S+) from (\S+) port ([0-9]+)(?:\s|$)`)
var sshTerminal = regexp.MustCompile(`(?:tty=|on )(pts/[0-9]+|tty[[:alnum:]]+)`)

func parseAcceptedSSH(message string, at time.Time, id string) (*LoginRecord, error) {
	m := acceptedSSH.FindStringSubmatch(message)
	if m == nil {
		return nil, nil
	}
	if net.ParseIP(m[3]) == nil {
		return nil, fmt.Errorf("SSH accepted login has invalid source IP %q", m[3])
	}
	terminal := "N/A"
	if tty := sshTerminal.FindStringSubmatch(message); tty != nil {
		terminal = tty[1]
	}
	return &LoginRecord{ID: id, Method: m[1], User: m[2], SourceIP: m[3], LoginTime: at, Terminal: terminal}, nil
}

type authLogFile struct {
	path     string
	modified time.Time
	identity string
}

func authLogFiles(path string) ([]authLogFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("auth log is not a regular file: %s", path)
	}
	paths, err := filepath.Glob(path + ".*")
	if err != nil {
		return nil, err
	}
	var files []authLogFile
	for _, p := range paths {
		if strings.HasSuffix(p, ".gz") || strings.HasSuffix(p, ".xz") || strings.HasSuffix(p, ".bz2") {
			continue
		}
		info, err := os.Stat(p)
		if err == nil && info.Mode().IsRegular() {
			files = append(files, authLogFile{p, info.ModTime(), authIdentity(info)})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modified.Equal(files[j].modified) {
			return files[i].path > files[j].path
		}
		return files[i].modified.Before(files[j].modified)
	})
	return append(files, authLogFile{path, info.ModTime(), authIdentity(info)}), nil
}

func authPrefix(f *os.File, size int) (string, error) {
	if size == 0 {
		return "", nil
	}
	b := make([]byte, size)
	if _, err := f.ReadAt(b, 0); err != nil {
		return "", err
	}
	return loginDigest(string(b)), nil
}

// Unix stat identities survive rename-based rotation. Other platforms retain
// the fixed-prefix fallback, which also supports copytruncate rotation.
func authIdentity(info os.FileInfo) string {
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	dev, ino := v.FieldByName("Dev"), v.FieldByName("Ino")
	if !dev.IsValid() || !ino.IsValid() || !dev.CanInterface() || !ino.CanInterface() {
		return ""
	}
	return fmt.Sprintf("%v:%v", dev.Interface(), ino.Interface())
}

func readAuthLogins(c LoginConfig, s *loginBaseline, now time.Time) ([]LoginRecord, bool, error) {
	files, err := authLogFiles(c.Path)
	if err != nil {
		return nil, false, fmt.Errorf("read auth log: %w", err)
	}
	start := len(files) - 1 // Initial scan reads the current file within Since.
	if s.Auth != nil && s.Auth.PrefixBytes > 0 {
		start = -1
		fallback := -1
		// Prefer the current file; after rotation the retained file matches
		// the fixed prefix and resumes at exactly the saved byte offset.
		for i := len(files) - 1; i >= 0; i-- {
			f, err := os.Open(files[i].path)
			if err != nil {
				return nil, false, err
			}
			info, statErr := f.Stat()
			prefix, prefixErr := authPrefix(f, s.Auth.PrefixBytes)
			f.Close()
			if statErr == nil && prefixErr == nil && info.Size() >= s.Auth.Offset && prefix == s.Auth.Prefix {
				if s.Auth.Identity == "" || authIdentity(info) == s.Auth.Identity {
					start = i
					break
				}
				if fallback < 0 {
					fallback = i
				}
			}
		}
		if start < 0 {
			start = fallback
		}
		if start < 0 {
			return nil, false, fmt.Errorf("auth log rotated/truncated beyond retained uncompressed files; saved cursor cannot be recovered (possible login gap)")
		}
	}
	var records []LoginRecord
	remaining := c.MaxRecords
	for i := start; i < len(files); i++ {
		cursor := s.Auth
		if i > start || cursor == nil {
			cursor = &authLogCursor{}
		}
		batch, next, count, eof, err := readAuthFile(files[i], cursor, remaining, s.Since, now)
		if err != nil {
			return nil, false, err
		}
		records = append(records, batch...)
		s.Auth = next
		remaining -= count
		if remaining == 0 || !eof {
			return records, true, nil
		}
	}
	return records, false, nil
}

func readAuthFile(file authLogFile, cursor *authLogCursor, limit int, since, now time.Time) ([]LoginRecord, *authLogCursor, int, bool, error) {
	f, err := os.Open(file.path)
	if err != nil {
		return nil, nil, 0, false, err
	}
	defer f.Close()
	next := *cursor
	info, err := f.Stat()
	if err != nil {
		return nil, nil, 0, false, err
	}
	if file.identity != "" && authIdentity(info) != file.identity {
		return nil, nil, 0, false, fmt.Errorf("auth log rotated during collection; retrying with the saved cursor is required")
	}
	if next.PrefixBytes > 0 {
		prefix, err := authPrefix(f, next.PrefixBytes)
		if err != nil || prefix != next.Prefix || info.Size() < next.Offset {
			return nil, nil, 0, false, fmt.Errorf("auth log changed during collection; retrying with the saved cursor is required")
		}
	}
	next.Identity = authIdentity(info)
	if next.PrefixBytes == 0 {
		next.PrefixBytes = int(min(info.Size(), 256))
		next.Prefix, err = authPrefix(f, next.PrefixBytes)
		if err != nil {
			return nil, nil, 0, false, err
		}
	}
	if _, err := f.Seek(next.Offset, io.SeekStart); err != nil {
		return nil, nil, 0, false, err
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	var records []LoginRecord
	count := 0
	for count < limit {
		line, err := readAuthLine(reader)
		if err == io.EOF {
			return records, &next, count, true, nil
		} // Keep an incomplete tail for the next scan.
		if err != nil {
			return nil, nil, 0, false, err
		}
		id := loginDigest(next.Prefix + ":" + strconv.FormatInt(next.Offset, 10) + ":" + line)
		record, err := parseAuthLine(line, now, id)
		if err != nil {
			return nil, nil, 0, false, fmt.Errorf("%s offset %d: %w", file.path, next.Offset, err)
		}
		if record != nil && !record.LoginTime.Before(since) {
			records = append(records, *record)
		}
		next.Offset += int64(len(line))
		count++
	}
	return records, &next, count, false, nil
}

func readAuthLine(reader *bufio.Reader) (string, error) {
	var line strings.Builder
	for {
		fragment, err := reader.ReadSlice('\n')
		if line.Len()+len(fragment) > 1024*1024 {
			return "", fmt.Errorf("auth log line exceeds 1 MiB")
		}
		line.Write(fragment)
		if err == bufio.ErrBufferFull {
			continue
		}
		return line.String(), err
	}
}

func parseAuthLine(line string, now time.Time, id string) (*LoginRecord, error) {
	if !strings.Contains(line, "sshd[") && !strings.Contains(line, "sshd-session[") && !strings.Contains(line, "sshd:") && !strings.Contains(line, "sshd-session:") {
		return nil, nil
	}
	if !acceptedSSH.MatchString(line) {
		return nil, nil
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil && len(line) >= 15 {
		// Traditional syslog omits the year and zone. Interpret it in the
		// monitored host's local zone and adjust across the December boundary.
		at, err = time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(now.In(time.Local).Year())+" "+line[:15], time.Local)
		if err == nil && at.After(now.Add(24*time.Hour)) {
			at = at.AddDate(-1, 0, 0)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid SSH auth log timestamp: %w", err)
	}
	return parseAcceptedSSH(line, at, id)
}
