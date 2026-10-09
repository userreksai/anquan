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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type HistoryConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Path           string `json:"path" yaml:"path"`
	Timezone       string `json:"timezone" yaml:"timezone"`
	PollIntervalMS int    `json:"poll_interval_ms" yaml:"poll_interval_ms"`
	MaxRecords     int    `json:"max_records" yaml:"max_records"`
	location       *time.Location
}

func normalizeHistory(c *Config, base string, rules pathRules) error {
	h := c.History
	if h == nil || !h.Enabled {
		return nil
	}
	if h.Path == "" {
		h.Path = "/var/log/history.log"
	}
	var err error
	if h.Path, err = rules.resolve(base, h.Path); err != nil {
		return fmt.Errorf("history.path: %w", err)
	}
	if h.Timezone == "" {
		h.Timezone = "Local"
	}
	if h.location, err = time.LoadLocation(h.Timezone); err != nil {
		return fmt.Errorf("history.timezone: %w", err)
	}
	if h.PollIntervalMS == 0 {
		h.PollIntervalMS = 1000
	}
	if h.PollIntervalMS < 100 || h.PollIntervalMS > 60000 {
		return fmt.Errorf("history.poll_interval_ms must be 100..60000")
	}
	if h.MaxRecords == 0 {
		h.MaxRecords = 100
	}
	if h.MaxRecords < 1 || h.MaxRecords > 1000 {
		return fmt.Errorf("history.max_records must be 1..1000")
	}
	if len(c.Server) == 0 {
		return fmt.Errorf("history.enabled requires at least one server")
	}
	return nil
}

type CommandRecord struct {
	ID          string    `json:"id"`
	CommandTime time.Time `json:"command_time"`
	User        string    `json:"user"`
	Terminal    string    `json:"terminal"`
	Command     string    `json:"command"`
	Path        string    `json:"path"`
	Offset      int64     `json:"offset"`
}

type historyEvent struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data"`
}

// Pending records and their next cursor are persisted together before sending.
// A restarted process retries the same IDs until every configured master ACKs.
type historyState struct {
	Version    int            `json:"version"`
	Source     string         `json:"source"`
	Generation string         `json:"generation"`
	Cursor     authLogCursor  `json:"cursor"`
	Anchor     string         `json:"anchor"`
	Pending    []historyEvent `json:"pending,omitempty"`
	Logged     bool           `json:"logged,omitempty"`
}

var historyPattern = regexp.MustCompile(`^\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\] \[([^\]\r\n]+)\] \[([^\]\r\n]+)\] \[(.*)\]$`)

func parseHistoryLine(line, path, id string, offset int64, location *time.Location) (CommandRecord, error) {
	var r CommandRecord
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if !utf8.ValidString(line) {
		return r, fmt.Errorf("history record is not valid UTF-8")
	}
	m := historyPattern.FindStringSubmatch(line)
	if m == nil || strings.TrimSpace(m[4]) == "" || len(m[2]) > 256 || len(m[3]) > 256 {
		return r, fmt.Errorf("expected [YYYY-MM-DD HH:MM:SS] [user] [terminal] [command]")
	}
	if location == nil {
		location = time.Local
	}
	at, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], location)
	if err != nil || at.Year() < 1970 {
		return r, fmt.Errorf("invalid command timestamp")
	}
	return CommandRecord{id, at, m[2], m[3], m[4], path, offset}, nil
}

func historyAnchor(f *os.File, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	n := min(offset, 256)
	b := make([]byte, int(n))
	if _, err := f.ReadAt(b, offset-n); err != nil {
		return "", err
	}
	return loginDigest(string(b)), nil
}

func readHistoryPage(c Config, s *historyState) (bool, error) {
	h := c.History
	f, err := os.Open(h.Path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("history log must be a regular file")
	}
	cur := &s.Cursor
	if info.Size() < cur.Offset || (cur.Identity != "" && authIdentity(info) != cur.Identity) {
		return false, fmt.Errorf("history log replaced or truncated; preserve the log and encrypted cursor before recovery")
	}
	prefix, err := authPrefix(f, cur.PrefixBytes)
	if err != nil || prefix != cur.Prefix {
		return false, fmt.Errorf("history log prefix changed; refusing to skip command records")
	}
	anchor, err := historyAnchor(f, cur.Offset)
	if err != nil || anchor != s.Anchor {
		return false, fmt.Errorf("history log changed before saved offset; refusing to skip command records")
	}
	if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
		return false, err
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := 0
	for n := 0; n < h.MaxRecords && bytesRead < 512*1024; n++ {
		line, readErr := readAuthLine(reader)
		if readErr == io.EOF {
			break
		} // Incomplete last line remains unconsumed.
		if readErr != nil {
			return false, readErr
		}
		offset := cur.Offset
		cur.Offset += int64(len(line))
		bytesRead += len(line)
		if strings.TrimSpace(line) == "" {
			continue
		}
		id := loginDigest(s.Generation + ":" + strconv.FormatInt(offset, 10))
		record, parseErr := parseHistoryLine(line, h.Path, id, offset, h.location)
		var event historyEvent
		if parseErr == nil {
			data, _ := json.Marshal(record)
			// Bound JSON bytes, including escaping, so the UDP envelope fits.
			if len(data) > 56000 {
				parseErr = fmt.Errorf("command record exceeds UDP event size limit")
			} else {
				event = historyEvent{id, "command_history", record.CommandTime, data}
			}
		}
		if parseErr != nil {
			data, _ := json.Marshal(Alert{Module: "history", Kind: "parse_error", Target: h.Path, Message: fmt.Sprintf("command record at byte %d: %v; original record retained in source log", offset, parseErr)})
			event = historyEvent{id, "alert", time.Now(), data}
		}
		s.Pending = append(s.Pending, event)
	}
	// Establish a fingerprint using consumed bytes only, so a partial initial
	// write cannot change the stored prefix before its complete record is read.
	cur.Identity = authIdentity(info)
	if cur.PrefixBytes == 0 {
		cur.PrefixBytes = int(min(cur.Offset, 256))
		cur.Prefix, err = authPrefix(f, cur.PrefixBytes)
		if err != nil {
			return false, err
		}
	}
	s.Anchor, err = historyAnchor(f, cur.Offset)
	if err != nil {
		return false, err
	}
	return bytesRead > 0 && cur.Offset < info.Size(), nil
}

type historySender func(Config, []historyEvent) error

// PollHistory performs one bounded page. It uses its own lock and cursor so a
// slow file scan cannot hold up command collection, or reset command history.
func PollHistory(c Config, writer io.Writer) (bool, error) {
	return pollHistory(c, writer, sendHistoryEvents)
}

func pollHistory(c Config, writer io.Writer, send historySender) (bool, error) {
	if c.History == nil || !c.History.Enabled {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
		return false, err
	}
	unlock, err := lockState(c.StateFile + ".commands.lock")
	if err != nil {
		return false, err
	}
	defer unlock()
	path := c.StateFile + ".commands"
	source := loginDigest(c.History.Path + "\x00" + c.History.Timezone)
	s := historyState{}
	err = readState(path, "history", &s)
	exists := err == nil
	if os.IsNotExist(err) {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return false, err
		}
		s = historyState{Version: 1, Source: source, Generation: hex.EncodeToString(random[:])}
	} else if err != nil {
		return false, err
	}
	if s.Version != 1 || s.Source != source || len(s.Generation) != 32 || s.Cursor.Offset < 0 || s.Cursor.PrefixBytes < 0 || s.Cursor.PrefixBytes > 256 || int64(s.Cursor.PrefixBytes) > s.Cursor.Offset {
		return false, fmt.Errorf("invalid command cursor or history source/timezone changed; preserve the encrypted .commands state before recovery")
	}
	more := len(s.Pending) > 0
	if len(s.Pending) == 0 {
		before := s.Cursor
		more, err = readHistoryPage(c, &s)
		if err != nil {
			return false, err
		}
		if before == s.Cursor && len(s.Pending) == 0 && exists {
			return false, nil
		}
		// The next offset and pending data form a durable encrypted outbox.
		if err := writeState(path, "history", s); err != nil {
			return false, err
		}
	}
	if len(s.Pending) == 0 {
		return more, nil
	}
	if !s.Logged {
		for _, event := range s.Pending {
			if err := writeLog(c, writer, time.Now(), event.Type, event.Data); err != nil {
				return false, err
			}
		}
		s.Logged = true
		if err := writeState(path, "history", s); err != nil {
			return false, err
		}
	}
	if err := send(c, s.Pending); err != nil {
		return false, err
	}
	s.Pending, s.Logged = nil, false
	if err := writeState(path, "history", s); err != nil {
		return false, err
	}
	return more, nil
}

func sendHistoryEvents(c Config, events []historyEvent) error {
	return sendHistoryEventsContext(context.Background(), c, events)
}

func sendHistoryEventsContext(ctx context.Context, c Config, events []historyEvent) error {
	if len(c.Server) == 0 {
		return fmt.Errorf("history has no master configured")
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	var failures []error
	for _, endpoint := range c.Server {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sendHistoryToMaster(ctx, c, host, endpoint, events); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", endpoint, err))
		}
	}
	return errors.Join(failures...)
}

func sendHistoryToMaster(ctx context.Context, c Config, host, endpoint string, events []historyEvent) error {
	conn, err := net.DialTimeout("udp", endpoint, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	ip := c.AgentIP
	if ip == "" {
		ip = conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := encodeUDPEvent(ip, host, event.Type, event.Time, event.ID, event.Data)
		if err != nil {
			return err
		}
		var envelope udpEnvelope
		if err := json.Unmarshal(b, &envelope); err != nil {
			return err
		}
		envelope.AckRequested = true
		b, err = json.Marshal(envelope)
		if err != nil {
			return err
		}
		if len(b) > 60000 {
			return fmt.Errorf("history event exceeds UDP datagram limit")
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		if _, err := conn.Write(b); err != nil {
			return err
		}
		var ack struct {
			Version int    `json:"version"`
			Type    string `json:"type"`
			EventID string `json:"event_id"`
		}
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return fmt.Errorf("waiting for master acknowledgement: %w", err)
			}
			if json.Unmarshal(buf[:n], &ack) == nil && ack.Version == 1 && ack.Type == "ack" && ack.EventID == envelope.EventID {
				break
			}
		}
	}
	return nil
}

func historyLoop(ctx context.Context, c Config, writer io.Writer) {
	if c.History == nil || !c.History.Enabled {
		return
	}
	var lastError string
	var lastReport time.Time
	for ctx.Err() == nil {
		more, err := pollHistory(c, writer, func(cfg Config, events []historyEvent) error {
			return sendHistoryEventsContext(ctx, cfg, events)
		})
		if err != nil {
			if lastError == "" || time.Since(lastReport) >= time.Minute {
				_ = writeLog(c, writer, time.Now(), "history_error", map[string]string{"path": c.History.Path, "error": err.Error()})
				lastError, lastReport = err.Error(), time.Now()
			}
		} else {
			lastError = ""
		}
		if more && err == nil {
			continue
		}
		timer := time.NewTimer(time.Duration(c.History.PollIntervalMS) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
