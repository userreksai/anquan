package security

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type logCursor struct {
	Identity string `json:"identity"`
	Epoch    string `json:"epoch,omitempty"`
	Offset   int64  `json:"offset"`
	Anchor   string `json:"anchor,omitempty"`
}
type auditGroup struct {
	ID       string    `json:"id"`
	AuditID  string    `json:"audit_id"`
	Records  []string  `json:"records"`
	Updated  time.Time `json:"updated"`
	Bytes    int       `json:"bytes"`
	Fragment int       `json:"fragment"`
}
type ioCursor struct {
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Complete   bool   `json:"complete"`
}
type collectorState struct {
	Version    int                    `json:"version"`
	Cursors    map[string]logCursor   `json:"cursors"`
	Audit      map[string]*auditGroup `json:"audit"`
	IOSessions map[string]string      `json:"io_sessions"`
	IOFiles    map[string]ioCursor    `json:"io_files"`
	PolicyHash string                 `json:"policy_hash,omitempty"`
}

func (m *Manager) loadCollectorState() (collectorState, error) {
	s := collectorState{Version: 1, Cursors: map[string]logCursor{}, Audit: map[string]*auditGroup{}, IOSessions: map[string]string{}, IOFiles: map[string]ioCursor{}}
	err := readPrivateJSON(m.statePath(), "security-collector", &s)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if s.Version != 1 {
		return s, errors.New("unsupported security collector state version")
	}
	return s, nil
}

// Poll checks one bounded batch. The transport queue must accept events durably;
// errors leave source cursors uncommitted, so the same stable IDs can be replayed.
func (m *Manager) Poll(ctx context.Context, emit func(Event) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.Config.Enabled {
		return nil
	}
	if emit == nil {
		return errors.New("security event callback is required")
	}
	transportEmit := emit
	emit = func(e Event) error {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if len(b) <= 40*1024 {
			return transportEmit(e)
		}
		source, _ := e.Data["source"].(string)
		path, _ := e.Data["path"].(string)
		return transportEmit(newEvent(source, "oversize_event", "warning", "Event exceeds transport size; original records remain in the host source log", e.ID, map[string]any{"path": path, "original_event_id": e.ID, "original_kind": e.Data["kind"], "serialized_bytes": len(b)}))
	}
	s, err := m.loadCollectorState()
	if err != nil {
		return fmt.Errorf("load collector state: %w", err)
	}
	if m.Config.Auditd.Enabled {
		if err = m.collectAudit(ctx, &s, emit); err != nil {
			return err
		}
	}
	if m.Config.Tetragon.Enabled {
		if err = m.collectLog(ctx, &s, "/var/log/tetragon/tetragon.log", "tetragon", func(line, key string) error {
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				return emit(newEvent("tetragon", "parse_error", "warning", "Tetragon emitted invalid JSON", key, map[string]any{"raw": line}))
			}
			kind := "runtime"
			for _, k := range []string{"process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_loader", "process_uprobe", "process_lsm", "process_usdt"} {
				if _, ok := event[k]; ok {
					kind = k
					break
				}
			}
			collected := newEvent("tetragon", kind, "info", "Tetragon "+kind, key, map[string]any{"event": event, "path": "/var/log/tetragon/tetragon.log"})
			if rawTime, ok := event["time"].(string); ok {
				if sourceTime, err := time.Parse(time.RFC3339Nano, rawTime); err == nil && !sourceTime.IsZero() {
					collected.Time = sourceTime.UTC()
				}
			}
			return emit(collected)
		}, emit); err != nil {
			return err
		}
	}
	if m.Config.Sudo.Enabled {
		if err = m.collectLog(ctx, &s, "/var/log/anquan-sudo.log", "sudo", func(line, key string) error {
			return emit(newEvent("sudo", "command", "info", line, key, map[string]any{"raw": line, "path": "/var/log/anquan-sudo.log"}))
		}, emit); err != nil {
			return err
		}
		if m.Config.Sudo.IOLogging {
			if err = m.collectSudoIO(ctx, &s, emit); err != nil {
				return err
			}
		}
	}
	checks := m.checkPolicies(ctx)
	raw, _ := json.Marshal(checks)
	digest := hashString(string(raw))
	if len(checks) > 0 && digest != s.PolicyHash {
		severity := "info"
		for _, c := range checks {
			if !c.Compliant {
				severity = "warning"
			}
		}
		if err = emit(newEvent("policies", "policy_check", severity, "Host policy compliance checked", digest+time.Now().UTC().Format("2006-01-02T15:04"), map[string]any{"mode": m.Config.Policies.Mode, "checks": checks})); err != nil {
			return err
		}
		s.PolicyHash = digest
	}
	return writePrivateJSON(m.statePath(), "security-collector", s)
}
func (m *Manager) collectLog(ctx context.Context, s *collectorState, path, source string, lineFn func(string, string) error, emit func(Event) error) error {
	oversizeFn := func(key string, bytes int64) error {
		return emit(newEvent(source, "oversize_record", "warning", "Log record exceeds 128KiB; original remains in the host source log", key, map[string]any{"path": path, "record_bytes": bytes}))
	}
	full := m.path(path)
	f, err := os.Open(full)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("collector source is not a regular file: %s", path)
	}
	current := fileIdentity(info)
	cursor := s.Cursors[path]
	if cursor.Identity != "" && cursor.Identity != current {
		// Drain the renamed file before switching to the new inode. Numeric
		// audit rotations and Tetragon timestamp rotations are both supported.
		entries, err := os.ReadDir(filepath.Dir(full))
		if err != nil {
			return err
		}
		found := false
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), filepath.Base(full)) {
				continue
			}
			candidate := filepath.Join(filepath.Dir(full), e.Name())
			ci, er := os.Stat(candidate)
			if er != nil || fileIdentity(ci) != cursor.Identity {
				continue
			}
			old, er := os.Open(candidate)
			if er != nil {
				return er
			}
			done, er := m.readLogBatch(ctx, old, path, &cursor, lineFn, oversizeFn)
			old.Close()
			if er != nil {
				return er
			}
			s.Cursors[path] = cursor
			found = true
			if !done {
				return nil
			}
			break
		}
		if !found {
			if err = emit(newEvent(source, "collection_gap", "warning", "Rotated source disappeared before it could be drained", path+cursor.Identity, map[string]any{"path": path, "offset": cursor.Offset})); err != nil {
				return err
			}
		}
		cursor = logCursor{Identity: current}
	}
	if cursor.Identity == "" {
		cursor.Identity = current
	}
	if info.Size() < cursor.Offset {
		if err = emit(newEvent(source, "collection_gap", "warning", "Source was truncated; continuing from the beginning", path+cursor.Identity+strconv.FormatInt(cursor.Offset, 10)+strconv.FormatInt(info.ModTime().UnixNano(), 10), map[string]any{"path": path, "previous_offset": cursor.Offset})); err != nil {
			return err
		}
		cursor.Offset = 0
		cursor.Anchor = ""
		cursor.Epoch = strconv.FormatInt(info.ModTime().UnixNano(), 10)
	}
	if cursor.Offset > 0 && cursor.Anchor != "" {
		anchor, err := sourceAnchor(f, cursor.Offset)
		if err != nil {
			return err
		}
		if anchor != cursor.Anchor {
			if err = emit(newEvent(source, "collection_gap", "warning", "Source contents changed before the saved cursor", path+cursor.Identity+anchor, map[string]any{"path": path})); err != nil {
				return err
			}
			cursor.Offset = 0
			cursor.Anchor = ""
			cursor.Epoch = strconv.FormatInt(info.ModTime().UnixNano(), 10)
		}
	}
	_, err = m.readLogBatch(ctx, f, path, &cursor, lineFn, oversizeFn)
	if err != nil {
		return err
	}
	s.Cursors[path] = cursor
	return nil
}
func sourceAnchor(f *os.File, offset int64) (string, error) {
	n := int64(128)
	if offset < n {
		n = offset
	}
	b := make([]byte, n)
	_, err := f.ReadAt(b, offset-n)
	if err != nil {
		return "", err
	}
	return hashString(string(b)), nil
}
func (m *Manager) readLogBatch(ctx context.Context, f *os.File, path string, cursor *logCursor, lineFn func(string, string) error, oversizeFn func(string, int64) error) (bool, error) {
	if _, err := f.Seek(cursor.Offset, io.SeekStart); err != nil {
		return false, err
	}
	reader := bufio.NewReaderSize(f, 128*1024)
	limit := 500
	if m.Config.MaxQueueEvents < limit {
		limit = m.Config.MaxQueueEvents
	}
	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		line, consumed, oversized, err := readBoundedLogLine(reader)
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		key := path + ":" + cursor.Identity + ":" + cursor.Epoch + ":" + strconv.FormatInt(cursor.Offset, 10)
		if oversized {
			err = oversizeFn(key, consumed)
		} else {
			err = lineFn(strings.TrimRight(line, "\r\n"), key)
		}
		if err != nil {
			return false, err
		}
		cursor.Offset += consumed
		cursor.Anchor, err = sourceAnchor(f, cursor.Offset)
		if err != nil {
			return false, err
		}
	}
	return false, nil
}
func readBoundedLogLine(reader *bufio.Reader) (string, int64, bool, error) {
	var b []byte
	var total int64
	oversized := false
	for {
		chunk, err := reader.ReadSlice('\n')
		total += int64(len(chunk))
		if total > 128*1024 {
			oversized = true
			b = nil
		}
		if !oversized {
			b = append(b, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", total, oversized, err
		}
		return string(b), total, oversized, nil
	}
}

var auditIDPattern = regexp.MustCompile(`msg=audit\(([0-9]+(?:\.[0-9]+)?:[0-9]+)\)`)
var auditFieldPattern = regexp.MustCompile(`(?:^|\s)([a-zA-Z0-9_]+)=("[^"]*"|'[^']*'|[^\s]+)`)

// Parse integer and fractional Unix seconds separately to retain audit's
// source precision during backfill and retries without floating-point rounding.
func auditSourceTime(id string) (time.Time, bool) {
	stamp, _, ok := strings.Cut(id, ":")
	if !ok {
		return time.Time{}, false
	}
	seconds, fraction, hasFraction := strings.Cut(stamp, ".")
	sec, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil || sec < 0 {
		return time.Time{}, false
	}
	var nanos int64
	if hasFraction {
		if len(fraction) == 0 || len(fraction) > 9 {
			return time.Time{}, false
		}
		nanos, err = strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
		if err != nil || nanos < 0 || nanos >= int64(time.Second) {
			return time.Time{}, false
		}
	}
	sourceTime := time.Unix(sec, nanos).UTC()
	if sourceTime.Year() > 9999 || sourceTime.Year() < 0 {
		return time.Time{}, false
	}
	return sourceTime, true
}

func auditFields(line string) map[string]string {
	m := map[string]string{}
	for _, v := range auditFieldPattern.FindAllStringSubmatch(line, -1) {
		value := strings.Trim(v[2], "\"'")
		if v[1] == "proctitle" || v[1] == "exe" || regexp.MustCompile(`^a[0-9]+$`).MatchString(v[1]) {
			if decoded, err := hex.DecodeString(value); err == nil && len(decoded) > 0 {
				value = strings.ReplaceAll(string(decoded), "\x00", " ")
			}
		}
		m[v[1]] = value
	}
	return m
}
func (m *Manager) auditLogPath() string {
	b, err := os.ReadFile(m.path("/etc/audit/auditd.conf"))
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			v := strings.SplitN(strings.SplitN(line, "#", 2)[0], "=", 2)
			if len(v) == 2 && strings.TrimSpace(v[0]) == "log_file" {
				p := strings.TrimSpace(v[1])
				if strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n") {
					return p
				}
			}
		}
	}
	return "/var/log/audit/audit.log"
}
func (m *Manager) collectAudit(ctx context.Context, s *collectorState, emit func(Event) error) error {
	flush := func(g *auditGroup) error {
		joined := strings.Join(g.Records, "\n")
		if !strings.Contains(joined, "anquan_") && !strings.Contains(joined, "type=USER_") && !strings.Contains(joined, "type=CRED_") && !strings.Contains(joined, "type=LOGIN ") {
			return nil
		}
		kind := "audit"
		if strings.Contains(joined, "anquan_exec") || strings.Contains(joined, "type=EXECVE") {
			kind = "exec"
		} else if strings.Contains(joined, "anquan_file") {
			kind = "file_change"
		}
		fields := map[string]string{}
		for _, record := range g.Records {
			for k, v := range auditFields(record) {
				if k != "type" {
					fields[k] = v
				}
			}
		}
		severity := "info"
		if fields["success"] == "no" || fields["res"] == "failed" {
			severity = "warning"
		}
		collected := newEvent("auditd", kind, severity, "Linux audit "+kind, g.ID+":"+strconv.Itoa(g.Fragment), map[string]any{"audit_id": g.AuditID, "records": g.Records, "fields": fields, "fragment": g.Fragment, "path": m.auditLogPath()})
		if sourceTime, ok := auditSourceTime(g.AuditID); ok {
			collected.Time = sourceTime
		}
		return emit(collected)
	}
	err := m.collectLog(ctx, s, m.auditLogPath(), "auditd", func(line, key string) error {
		id := auditIDPattern.FindStringSubmatch(line)
		if len(id) != 2 {
			return nil
		}
		g := s.Audit[id[1]]
		if g == nil {
			g = &auditGroup{ID: key, AuditID: id[1]}
			s.Audit[id[1]] = g
		}
		if g.Bytes+len(line) > 24*1024 {
			if err := flush(g); err != nil {
				return err
			}
			g.Records = nil
			g.Bytes = 0
			g.Fragment++
		}
		g.Records = append(g.Records, line)
		g.Bytes += len(line)
		g.Updated = time.Now().UTC()
		if strings.Contains(line, "type=EOE ") {
			if err := flush(g); err != nil {
				return err
			}
			delete(s.Audit, id[1])
		}
		return nil
	}, emit)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(s.Audit) {
		g := s.Audit[key]
		if time.Since(g.Updated) >= 2*time.Second {
			if err = flush(g); err != nil {
				return err
			}
			delete(s.Audit, key)
		}
	}
	if len(s.Audit) > 10000 {
		return errors.New("too many incomplete audit groups; review audit log format")
	}
	return nil
}

var sudoNames = map[string]bool{"log": true, "log.json": true, "timing": true, "stdin": true, "stdout": true, "stderr": true, "ttyin": true, "ttyout": true}

func (m *Manager) collectSudoIO(ctx context.Context, s *collectorState, emit func(Event) error) error {
	base := m.path("/var/log/anquan-sudo-io")
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return nil
	}
	type entry struct {
		path, rel string
		info      os.FileInfo
	}
	groups := map[string][]entry{}
	count := 0
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !sudoNames[d.Name()] {
			return nil
		}
		count++
		if count > 50000 {
			return errors.New("sudo I/O file scan exceeds 50000 entries; archive old sessions")
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, e := filepath.Rel(base, p)
		if e != nil {
			return e
		}
		session := filepath.ToSlash(filepath.Dir(rel))
		if session == "." {
			return nil
		}
		groups[session] = append(groups[session], entry{p, filepath.ToSlash(rel), info})
		return nil
	})
	if err != nil {
		return err
	}
	chunks := 0
	for _, session := range sortedKeys(groups) {
		files := groups[session]
		sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
		id := hashString("sudo-session:" + session)[:32]
		var total int64
		var latest time.Time
		metadata := []map[string]any{}
		for _, f := range files {
			total += f.info.Size()
			if f.info.ModTime().After(latest) {
				latest = f.info.ModTime()
			}
			metadata = append(metadata, map[string]any{"file": filepath.Base(f.path), "size": f.info.Size(), "modified_at": f.info.ModTime().UTC()})
		}
		raw, _ := json.Marshal(metadata)
		digest := hashString(string(raw))
		if s.IOSessions[session] != digest {
			if err = emit(newEvent("sudo", "io_session", "info", "sudo input/output session index", id+digest, map[string]any{"session_id": id, "files": metadata, "metadata_only": !m.Config.Sudo.UploadIO, "total_size": total})); err != nil {
				return err
			}
			s.IOSessions[session] = digest
		}
		if !m.Config.Sudo.UploadIO {
			continue
		}
		if total > int64(m.Config.Sudo.MaxSessionBytes) {
			if err = emit(newEvent("sudo", "io_limit", "warning", "sudo I/O session exceeds max_session_bytes", id+strconv.FormatInt(total, 10), map[string]any{"session_id": id, "total_size": total, "limit": m.Config.Sudo.MaxSessionBytes})); err != nil {
				return err
			}
			continue
		}
		// A session must have no recent writes; live stream replay is intentionally
		// not claimed. Later writes create a new file generation and upload again.
		stable := time.Duration(m.Config.PollIntervalSeconds*2) * time.Second
		if stable < 5*time.Second {
			stable = 5 * time.Second
		}
		if time.Since(latest) < stable {
			continue
		}
		for _, f := range files {
			if f.info.Size() > 64*1024*1024 {
				if err = emit(newEvent("sudo", "io_limit", "warning", "sudo I/O file exceeds 64MiB transport limit", id+f.rel+strconv.FormatInt(f.info.Size(), 10), map[string]any{"session_id": id, "file": filepath.Base(f.path), "total_size": f.info.Size()})); err != nil {
					return err
				}
				continue
			}
			generation := digest[:32]
			cursor := s.IOFiles[f.rel]
			if cursor.Generation != generation {
				cursor = ioCursor{Generation: generation}
			}
			if cursor.Complete {
				continue
			}
			if chunks >= 32 {
				return nil
			}
			file, e := os.Open(f.path)
			if e != nil {
				return e
			}
			if _, e = file.Seek(cursor.Offset, io.SeekStart); e != nil {
				file.Close()
				return e
			}
			for !cursor.Complete && chunks < 32 {
				buf := make([]byte, 24*1024)
				n, e := file.Read(buf)
				if e != nil && e != io.EOF {
					file.Close()
					return e
				}
				complete := cursor.Offset+int64(n) >= f.info.Size()
				details := map[string]any{"session_id": id, "file": filepath.Base(f.path), "generation": generation, "offset": cursor.Offset, "content_base64": base64.StdEncoding.EncodeToString(buf[:n]), "total_size": f.info.Size(), "complete": complete}
				e = emit(newEvent("sudo", "io_chunk", "info", "sudo I/O file data", id+f.rel+generation+strconv.FormatInt(cursor.Offset, 10), map[string]any{"details": details}))
				if e != nil {
					file.Close()
					return e
				}
				cursor.Offset += int64(n)
				cursor.Complete = complete
				s.IOFiles[f.rel] = cursor
				chunks++
				if n == 0 && !complete {
					file.Close()
					return errors.New("sudo I/O source changed during read")
				}
			}
			file.Close()
		}
	}
	return nil
}
