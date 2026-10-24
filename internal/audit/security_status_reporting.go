package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"anqu/internal/security"
)

const componentStatusSnapshotInterval = 5 * time.Minute

func componentStatusSnapshotPeriod(checkSeconds int) time.Duration {
	if checkSeconds <= 0 {
		checkSeconds = 30
	}
	// Status is sampled on the configured check tick. Advertise the actual
	// refresh period, including long or non-dividing check intervals.
	checks := max(1, (300+checkSeconds-1)/checkSeconds)
	return time.Duration(checks*checkSeconds) * time.Second
}

// Include native worker health after enrichment, not just the manager's own
// components. Queue counters and sample timestamps must not create a change.
func componentStatusFingerprint(data map[string]any) (string, error) {
	raw, err := json.Marshal(data["components"])
	if err != nil {
		return "", err
	}
	var components []map[string]any
	if err := json.Unmarshal(raw, &components); err != nil {
		return "", err
	}
	projected := make([]map[string]any, 0, len(components))
	for _, component := range components {
		fields := map[string]any{}
		for _, key := range []string{"name", "enabled", "installed", "running", "state", "message", "error", "version", "config_hash", "policy_mode", "checks", "omitted_checks"} {
			if value, ok := component[key]; ok {
				fields[key] = value
			}
		}
		projected = append(projected, fields)
	}
	sort.SliceStable(projected, func(i, j int) bool {
		left, _ := projected[i]["name"].(string)
		right, _ := projected[j]["name"].(string)
		return left < right
	})
	// A changed local account list must reach the selected machine's editor on
	// the next status check. Sampling time alone must not defeat deduplication.
	var inventory struct {
		SSHAccounts map[string]any `json:"ssh_accounts"`
	}
	inventoryJSON, err := json.Marshal(data["inventory"])
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(inventoryJSON, &inventory); err != nil {
		return "", err
	}
	delete(inventory.SSHAccounts, "checked_at")
	raw, err = json.Marshal(map[string]any{"components": projected, "config_hash": data["config_hash"], "ssh_accounts": inventory.SSHAccounts})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

type componentStatusReporter struct {
	mu               sync.Mutex
	fingerprint      string
	lastSent         time.Time
	snapshotInterval time.Duration
}

func (r *componentStatusReporter) emit(event security.Event, persist func(security.Event) error) error {
	if event.Type != "component_status" {
		return persist(event)
	}
	fingerprint, err := componentStatusFingerprint(event.Data)
	if err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	interval := max(componentStatusSnapshotInterval, r.snapshotInterval)
	unchanged := r.fingerprint == fingerprint
	if unchanged && event.Time.Sub(r.lastSent) >= 0 && event.Time.Sub(r.lastSent) < interval {
		return nil
	}
	if event.Data == nil {
		event.Data = map[string]any{}
	}
	event.Data["status_reporting"] = "changes_only"
	event.Data["snapshot_interval_seconds"] = int(interval / time.Second)
	if unchanged {
		event.Data["snapshot_only"] = true
	} else {
		delete(event.Data, "snapshot_only")
	}
	if err := persist(event); err != nil {
		return err
	}
	// A failed durable enqueue never consumes the change or refresh interval.
	r.fingerprint, r.lastSent = fingerprint, event.Time
	return nil
}
