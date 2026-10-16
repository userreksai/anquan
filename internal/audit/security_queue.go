package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"anqu/internal/security"
)

const maxSecurityQueueBytes int64 = 256 << 20

type queuedSecurityEvent struct {
	Version      int             `json:"version"`
	Event        security.Event  `json:"event"`
	Targets      []string        `json:"targets"`
	Acknowledged map[string]bool `json:"acknowledged,omitempty"`
}

// Each encrypted record is persisted before its source cursor may advance.
// Independent files keep enqueue cost bounded even during a prolonged outage.
type securityQueue struct {
	mu    sync.Mutex
	dir   string
	limit int
	files map[string]string
	bytes int64
}

func openSecurityQueue(c Config) (*securityQueue, error) {
	q := &securityQueue{dir: filepath.Join(securityDataDir(c), "outbox"), limit: 10000, files: map[string]string{}}
	if c.Security != nil && c.Security.MaxQueueEvents > 0 {
		q.limit = c.Security.MaxQueueEvents
	}
	if err := os.MkdirAll(q.dir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".age") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 {
			return nil, fmt.Errorf("invalid security queue record %s", entry.Name())
		}
		var record queuedSecurityEvent
		if err := readState(filepath.Join(q.dir, entry.Name()), "security-event", &record); err != nil {
			return nil, err
		}
		if record.Version != 1 || len(record.Targets) == 0 || record.Event.ID == "" {
			return nil, fmt.Errorf("invalid security queue record")
		}
		key := securityEventKey(record.Event)
		if _, ok := q.files[key]; ok {
			return nil, fmt.Errorf("duplicate security queue identity")
		}
		q.files[key] = entry.Name()
		q.bytes += info.Size()
	}
	return q, nil
}

func securityEventKey(event security.Event) string {
	sum := sha256.Sum256([]byte(event.Type + "\x00" + event.ID))
	return hex.EncodeToString(sum[:])
}

func (q *securityQueue) enqueue(c Config, event security.Event) error {
	if event.Type != "security_event" && event.Type != "component_status" {
		return fmt.Errorf("unsupported security event type")
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	data, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}
	if len(data) > 50000 {
		return fmt.Errorf("security event exceeds 50000-byte data limit")
	}
	if event.ID == "" {
		sum := sha256.Sum256(append([]byte(event.Type+event.Time.UTC().Format(time.RFC3339Nano)), data...))
		event.ID = hex.EncodeToString(sum[:])
	}
	key := securityEventKey(event)
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, exists := q.files[key]; exists {
		return nil
	}
	if len(c.Server) == 0 {
		return fmt.Errorf("security event has no destination")
	}
	if len(q.files) >= q.limit || q.bytes >= maxSecurityQueueBytes {
		return fmt.Errorf("security outbox full; source cursor retained (events=%d,bytes=%d)", len(q.files), q.bytes)
	}
	record := queuedSecurityEvent{Version: 1, Event: event, Targets: append([]string(nil), c.Server...), Acknowledged: map[string]bool{}}
	name := event.Time.UTC().Format("20060102T150405.000000000") + "-" + key + ".age"
	path := filepath.Join(q.dir, name)
	if err := writeState(path, "security-event", record); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	q.files[key] = name
	q.bytes += info.Size()
	return nil
}

func (q *securityQueue) stats() map[string]any {
	q.mu.Lock()
	defer q.mu.Unlock()
	return map[string]any{"pending": len(q.files), "bytes": q.bytes, "max_events": q.limit, "max_bytes": maxSecurityQueueBytes}
}

// Targets and individual ACKs survive config changes and process restarts.
// One unreachable target cannot prevent attempting the other targets.
func (q *securityQueue) drain(ctx context.Context, c Config, send func(context.Context, Config, string, []historyEvent) error) (bool, error) {
	q.mu.Lock()
	names := make([]string, 0, len(q.files))
	for _, name := range q.files {
		names = append(names, name)
	}
	q.mu.Unlock()
	sort.Strings(names)
	var failures []error
	failedTargets := map[string]bool{}
	processed := 0
	for _, name := range names {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		path := filepath.Join(q.dir, name)
		var record queuedSecurityEvent
		if err := readState(path, "security-event", &record); err != nil {
			return false, err
		}
		data, err := json.Marshal(record.Event.Data)
		if err != nil {
			return false, err
		}
		if record.Acknowledged == nil {
			record.Acknowledged = map[string]bool{}
		}
		all := true
		attempted := false
		for _, target := range record.Targets {
			if record.Acknowledged[target] {
				continue
			}
			if failedTargets[target] {
				all = false
				continue
			}
			attempted = true
			e := historyEvent{ID: record.Event.ID, Type: record.Event.Type, Time: record.Event.Time, Data: data}
			if err := send(ctx, c, target, []historyEvent{e}); err != nil {
				all = false
				failedTargets[target] = true
				failures = append(failures, fmt.Errorf("%s: %w", target, err))
				continue
			}
			record.Acknowledged[target] = true
			q.mu.Lock()
			old, _ := os.Stat(path)
			err = writeState(path, "security-event", record)
			if err == nil {
				next, _ := os.Stat(path)
				if old != nil && next != nil {
					q.bytes += next.Size() - old.Size()
				}
			}
			q.mu.Unlock()
			if err != nil {
				return false, err
			}
		}
		if all {
			q.mu.Lock()
			info, _ := os.Stat(path)
			err = os.Remove(path)
			if err == nil {
				delete(q.files, securityEventKey(record.Event))
				if info != nil {
					q.bytes -= info.Size()
				}
			}
			q.mu.Unlock()
			if err != nil {
				return false, err
			}
		}
		if attempted {
			processed++
		}
		if processed >= 64 {
			break
		}
	}
	q.mu.Lock()
	more := len(q.files) > 0
	q.mu.Unlock()
	return more, errors.Join(failures...)
}

func sendSecurityToMaster(ctx context.Context, c Config, target string, events []historyEvent) error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	return sendHistoryToMaster(ctx, c, host, target, events)
}
