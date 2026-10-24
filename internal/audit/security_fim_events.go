package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"anqu/internal/security"
)

const nativeFIMBacklogLimit = 2048

// These portable mask values are Linux inotify's public ABI. Keeping the
// normalization here makes transition/debounce tests runnable on every OS.
const (
	nativeModify     = uint32(0x00000002)
	nativeAttrib     = uint32(0x00000004)
	nativeCloseWrite = uint32(0x00000008)
	nativeMovedFrom  = uint32(0x00000040)
	nativeMovedTo    = uint32(0x00000080)
	nativeCreate     = uint32(0x00000100)
	nativeDelete     = uint32(0x00000200)
	nativeDeleteSelf = uint32(0x00000400)
	nativeMoveSelf   = uint32(0x00000800)
	nativeIsDir      = uint32(0x40000000)
)

type nativeFIMObservation struct {
	Path     string
	After    *nativeFile
	At       time.Time
	Observed bool
}

func nativeEffectiveFile(state *nativeFIMState, path string) (nativeFile, bool) {
	n, has := state.Files[path]
	apply := func(change *nativeFIMChange) {
		if change != nil && change.Path == path {
			if change.After == nil {
				n, has = nativeFile{}, false
			} else {
				n, has = *change.After, true
			}
		}
	}
	apply(state.Pending)
	for i := range state.Backlog {
		apply(&state.Backlog[i])
	}
	return n, has
}

func nativeLoadState(c Config) (string, *nativeFIMState, func(), error) {
	path := filepath.Join(securityDataDir(c), "native-fim.state")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", nil, nil, err
	}
	unlock, err := lockState(path + ".lock")
	if err != nil {
		return "", nil, nil, err
	}
	state := &nativeFIMState{}
	if err := readState(path, "security-fim", state); err != nil {
		if !os.IsNotExist(err) {
			unlock()
			return "", nil, nil, err
		}
		var generation [16]byte
		if _, err := rand.Read(generation[:]); err != nil {
			unlock()
			return "", nil, nil, err
		}
		state = &nativeFIMState{Version: 1, Generation: hex.EncodeToString(generation[:]), Files: map[string]nativeFile{}}
	}
	if state.Version != 1 || state.Generation == "" || state.Files == nil || len(state.Backlog) > nativeFIMBacklogLimit {
		unlock()
		return "", nil, nil, fmt.Errorf("invalid persistent native FIM baseline")
	}
	// Excluded editor files from old releases disappear without a deletion alert.
	for p, n := range state.Files {
		if nativeExcluded(c, p) || !nativeInScope(p, c.Security.NativeFIM.Paths) {
			delete(state.Files, p)
		} else {
			state.Files[p] = nativeContentPolicy(p, n, c.Security.NativeFIM)
		}
	}
	if state.Pending != nil && nativeExcluded(c, state.Pending.Path) {
		state.Pending = nil
	}
	kept := state.Backlog[:0]
	for _, change := range state.Backlog {
		if !nativeExcluded(c, change.Path) {
			kept = append(kept, change)
		}
	}
	state.Backlog = kept
	// Explicitly disabling capture or a newly recognized sensitive pathname also
	// scrubs reserved records before replay; it never exposes stale plaintext.
	scrub := func(change *nativeFIMChange) {
		if change == nil {
			return
		}
		if change.After != nil {
			n := nativeContentPolicy(change.Path, *change.After, c.Security.NativeFIM)
			change.After = &n
		}
		if details, ok := change.Event.Data["details"].(map[string]any); ok {
			nativeScrubReservedContent(change.Path, details, c.Security.NativeFIM)
		}
	}
	scrub(state.Pending)
	for i := range state.Backlog {
		scrub(&state.Backlog[i])
	}
	return path, state, unlock, nil
}

func nativePlanObservation(state *nativeFIMState, c Config, o nativeFIMObservation) error {
	if nativeExcluded(c, o.Path) || !nativeInScope(o.Path, c.Security.NativeFIM.Paths) {
		return nil
	}
	before, had := nativeEffectiveFile(state, o.Path)
	after, has := nativeFile{}, o.After != nil
	if has {
		after = *o.After
	}
	// A newly assigned root starts with a baseline even when it does not yet
	// exist. Retaining that absence lets its first later creation be an added
	// event without creating the optional file or reporting a startup failure.
	if !nativeInScope(o.Path, state.Roots) && has && !o.Observed {
		state.Files[o.Path] = after
		return nil
	}
	if has && after.Type == "missing" && !had {
		state.Files[o.Path] = after
		return nil
	}
	if had && before.Type == "missing" && (!has || after.Type == "missing") {
		return nil
	}
	if has && after.Type == "file" {
		after.ContentTracked = before.ContentTracked || (nativeCaptureCreated(c.Security.NativeFIM) && (!had || before.Type != "file"))
		after = nativeContentPolicy(o.Path, after, c.Security.NativeFIM)
	}
	before = nativeContentPolicy(o.Path, before, c.Security.NativeFIM)
	if had && has && nativeSameMetadata(before, after) {
		// Capture-policy changes are baseline maintenance, not file changes.
		if after.ContentStatus == "unavailable" && before.SHA256 != "" {
			return nil
		}
		if state.Pending == nil && len(state.Backlog) == 0 {
			state.Files[o.Path] = after
		}
		return nil
	}
	if !had && !has && !o.Observed {
		return nil
	}
	if !had && !has {
		before = nativeFile{Type: "file", ContentStatus: "unavailable", ContentTracked: nativeCaptureCreated(c.Security.NativeFIM)}
		had = true
	}
	change := "modified"
	if !had {
		change = "added"
	}
	if !has {
		change = "deleted"
	}
	if has && after.Type == "missing" {
		// Polling and real-time deletion share the same public transition.
		// The missing value remains as the exact root's durable tombstone.
		change = "deleted"
	}
	if had && before.Type == "missing" && has && after.Type != "missing" {
		change = "added"
	}
	if len(state.Backlog) >= nativeFIMBacklogLimit {
		return fmt.Errorf("native FIM durable transition backlog full; reconciliation required")
	}
	beforeMeta, afterMeta := before, after
	beforeMeta.Text, afterMeta.Text = "", ""
	beforeMeta.ContentStatus, afterMeta.ContentStatus = "", ""
	beforeMeta.TextTruncated, afterMeta.TextTruncated = false, false
	details := map[string]any{"change": change, "before": beforeMeta, "after": afterMeta, "baseline_persistent": true}
	nativeContentDetails(details, "previous", o.Path, before, had && before.Type != "missing", c.Security.NativeFIM)
	nativeContentDetails(details, "current", o.Path, after, has && after.Type != "missing", c.Security.NativeFIM)
	state.Sequence++
	when := o.At
	if when.IsZero() {
		when = time.Now().UTC()
	}
	event := security.Event{ID: fmt.Sprintf("native-fim:%s:%d", state.Generation, state.Sequence), Type: "security_event", Time: when, Component: "native_fim", Message: "monitored file changed", Data: map[string]any{"source": "native_fim", "kind": "file_change", "severity": "warning", "path": o.Path, "message": "monitored file " + change, "details": details}}
	if err := nativeBoundEvent(&event); err != nil {
		return err
	}
	reserved := nativeFIMChange{Event: event, Path: o.Path}
	if has {
		reserved.After = &after
	} else {
		// Exact roots are represented as missing by WalkDir reconciliation.
		// Keep the same tombstone after a real-time delete, avoiding a second
		// "missing" notification for the very same removal.
		for _, root := range c.Security.NativeFIM.Paths {
			if filepath.Clean(root) == filepath.Clean(o.Path) {
				missing := nativeFile{Type: "missing", ContentStatus: "not_applicable"}
				reserved.After = &missing
				break
			}
		}
	}
	if state.Pending == nil {
		state.Pending = &reserved
	} else {
		state.Backlog = append(state.Backlog, reserved)
	}
	return nil
}

// accepted means the entire observed batch is durable even if its destination
// queue is currently full. The caller may then release its in-memory snapshots.
func nativeApplyObservations(c Config, observations []nativeFIMObservation, emit func(security.Event) error) (accepted bool, err error) {
	path, state, unlock, err := nativeLoadState(c)
	if err != nil {
		return false, err
	}
	defer unlock()
	priorErr := commitNativeFIMChange(path, state, emit)
	for _, o := range nativeCoalesceReplacements(state, observations) {
		if err := nativePlanObservation(state, c, o); err != nil {
			return false, errors.Join(priorErr, err)
		}
	}
	if err := writeState(path, "security-fim", state); err != nil {
		return false, errors.Join(priorErr, err)
	}
	return true, commitNativeFIMChange(path, state, emit)
}

// Editors can move the old file to a backup and recreate the original path
// during one save. Use the baseline at the start of this batch and the final
// captured version to report that replacement once, with both contents. A new
// file's create/delete lifecycle and a final deletion remain separate evidence.
// This runs before reserving identities; already-published events are untouched.
// The caller supplies at most one buffered burst per path in each batch.
func nativeCoalesceReplacements(state *nativeFIMState, observations []nativeFIMObservation) []nativeFIMObservation {
	type candidate struct {
		last    int
		removed bool
	}
	paths := make(map[string]candidate)
	for i, observation := range observations {
		item := paths[observation.Path]
		item.last = i
		item.removed = item.removed || observation.After == nil
		paths[observation.Path] = item
	}
	merged := make(map[string]int)
	for path, item := range paths {
		before, had := nativeEffectiveFile(state, path)
		after := observations[item.last].After
		if item.removed && had && before.Type == "file" && after != nil && after.Type == "file" {
			merged[path] = item.last
		}
	}
	if len(merged) == 0 {
		return observations
	}
	result := make([]nativeFIMObservation, 0, len(observations))
	for i, observation := range observations {
		if last, ok := merged[observation.Path]; !ok || i == last {
			result = append(result, observation)
		}
	}
	return result
}

// Unlike the legacy MD5 module, the baseline and reserved transitions survive
// restarts and assignments. New roots initialize without uploading old files.
func pollNativeFIM(ctx context.Context, c Config, emit func(security.Event) error) error {
	return reconcileNativeFIM(ctx, c, nil, emit)
}

func reconcileNativeFIM(ctx context.Context, c Config, skip map[string]bool, emit func(security.Event) error) error {
	path, state, unlock, err := nativeLoadState(c)
	if err != nil {
		return err
	}
	defer unlock()
	priorErr := commitNativeFIMChange(path, state, emit)
	next, err := nativeSnapshot(ctx, c, state)
	if err != nil {
		return errors.Join(priorErr, err)
	}
	all := map[string]bool{}
	for p := range next {
		all[p] = true
	}
	for p := range state.Files {
		all[p] = true
	}
	if state.Pending != nil {
		all[state.Pending.Path] = true
	}
	for _, change := range state.Backlog {
		all[change.Path] = true
	}
	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if skip[p] {
			continue
		}
		o := nativeFIMObservation{Path: p}
		if n, has := next[p]; has {
			o.After = &n
		}
		if err := nativePlanObservation(state, c, o); err != nil {
			return errors.Join(priorErr, err)
		}
	}
	state.Roots = append([]string(nil), c.Security.NativeFIM.Paths...)
	if err := writeState(path, "security-fim", state); err != nil {
		return errors.Join(priorErr, err)
	}
	return commitNativeFIMChange(path, state, emit)
}

type nativeFIMBurst struct {
	First  time.Time
	Last   time.Time
	Stages []nativeFIMObservation
}

func nativeAccumulate(bursts map[string]*nativeFIMBurst, activity nativeWatchEvent) error {
	when := activity.At
	if when.IsZero() {
		when = time.Now()
	}
	b := bursts[activity.Path]
	if b == nil {
		if len(bursts) >= 1024 {
			return fmt.Errorf("native FIM observation buffer full; reconciliation required")
		}
		b = &nativeFIMBurst{First: when}
		bursts[activity.Path] = b
	}
	b.Last = when
	o := nativeFIMObservation{Path: activity.Path, At: when, Observed: true}
	if activity.Mask&(nativeDelete|nativeMovedFrom|nativeDeleteSelf|nativeMoveSelf) == 0 {
		o.After = activity.Snapshot
		if o.After == nil || o.After.Type == "missing" {
			typ := "file"
			if activity.Mask&nativeIsDir != 0 {
				typ = "directory"
			}
			n := nativeFile{Type: typ, ContentStatus: "unavailable"}
			o.After = &n
		}
	}
	// Writes and attribute masks within one alive generation collapse to its
	// last stable capture. A delete/create boundary is never merged away.
	if len(b.Stages) > 0 && (b.Stages[len(b.Stages)-1].After == nil) == (o.After == nil) {
		prior := &b.Stages[len(b.Stages)-1]
		if o.After != nil && o.After.ContentStatus == "unavailable" && prior.After != nil && prior.After.SHA256 != "" {
			return nil
		}
		*prior = o
		return nil
	}
	if len(b.Stages) >= 64 {
		return fmt.Errorf("native FIM per-path transition buffer full; reconciliation required")
	}
	total := 0
	for _, pending := range bursts {
		total += len(pending.Stages)
	}
	if total >= 1024 {
		return fmt.Errorf("native FIM observation transition buffer full; reconciliation required")
	}
	b.Stages = append(b.Stages, o)
	return nil
}

// Directory notifications also cover ancestors of an optional root. A newly
// available tree can already contain files by the time its watches are added;
// reconcile it promptly rather than waiting for the periodic safety scan.
func nativeDirectoryChange(activity nativeWatchEvent, roots []string) bool {
	if activity.Mask&(nativeCreate|nativeMovedTo|nativeDelete|nativeMovedFrom|nativeDeleteSelf|nativeMoveSelf) == 0 {
		return false
	}
	if activity.Mask&(nativeIsDir|nativeDeleteSelf|nativeMoveSelf) != 0 ||
		(activity.Snapshot != nil && activity.Snapshot.Type == "directory") {
		return true
	}
	for _, root := range roots {
		if activity.Path != root && inside(activity.Path, root) {
			return true
		}
	}
	return false
}

func nativeFIMLoop(ctx context.Context, c Config, emit func(security.Event) error, health func(error)) {
	capture := func(path string, mask uint32) *nativeFile {
		if mask&(nativeCreate|nativeMovedTo|nativeModify|nativeAttrib|nativeCloseWrite) == 0 {
			return nil
		}
		n, err := nativeReadFile(ctx, path, c.Security.NativeFIM, c.Security.NativeFIM.ReportChanges || nativeCaptureCreated(c.Security.NativeFIM), false)
		if err != nil {
			return nil
		}
		return &n
	}
	watch, closeWatch := watchNativePaths(ctx, c.Security.NativeFIM.Paths, func(path string) bool { return nativeExcluded(c, path) }, capture)
	defer closeWatch()
	health(pollNativeFIM(ctx, c, emit))
	interval := c.Security.NativeFIM.PollIntervalSeconds
	if interval <= 0 {
		interval = 30
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	flush := time.NewTicker(50 * time.Millisecond)
	defer flush.Stop()
	bursts := map[string]*nativeFIMBurst{}
	var directoryFirst, directoryLast time.Time
	requestReconcile := func() {
		directoryLast = time.Now()
		if directoryFirst.IsZero() {
			directoryFirst = directoryLast
		}
	}
	markDirectoryChange := func(activity nativeWatchEvent) {
		if nativeDirectoryChange(activity, c.Security.NativeFIM.Paths) {
			requestReconcile()
		}
	}
	flushReady := func(force bool) {
		paths := make([]string, 0, len(bursts))
		for p, b := range bursts {
			if force || time.Since(b.Last) >= 200*time.Millisecond || time.Since(b.First) >= 2*time.Second {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)
		var batch []nativeFIMObservation
		for _, p := range paths {
			batch = append(batch, bursts[p].Stages...)
		}
		if len(batch) == 0 {
			return
		}
		accepted, err := nativeApplyObservations(c, batch, emit)
		if accepted {
			for _, p := range paths {
				delete(bursts, p)
			}
		}
		health(err)
	}
	reconcile := func() error {
		skip := map[string]bool{}
		for p := range bursts {
			skip[p] = true
		}
		return reconcileNativeFIM(ctx, c, skip, emit)
	}
	for {
		select {
		case <-ctx.Done():
			// Stop the producer, then preserve snapshots it already captured.
			closeWatch()
			if watch != nil {
				for activity := range watch {
					if activity.Err == nil && activity.Path != "" && nativeInScope(activity.Path, c.Security.NativeFIM.Paths) && !nativeExcluded(c, activity.Path) {
						if err := nativeAccumulate(bursts, activity); err != nil {
							health(err)
						}
					}
				}
			}
			flushReady(true)
			return
		case activity, ok := <-watch:
			if !ok {
				watch = nil
				continue
			}
			if activity.Err != nil {
				health(activity.Err)
				requestReconcile()
				// Diagnostic failures remain visible, but ordinary raw kernel masks
				// are never separate runtime events or notifications.
				err := emit(security.Event{Type: "security_event", Time: time.Now().UTC(), Component: "native_fim", Data: map[string]any{"source": "native_fim", "kind": "watch_error", "severity": "warning", "path": activity.Path, "message": activity.Err.Error()}})
				if err != nil {
					health(err)
				}
				continue
			}
			// The ancestor itself need not be in scope: creating /var/spool
			// must activate a still-missing /var/spool/cron root as it appears.
			if activity.Path != "" && !nativeExcluded(c, activity.Path) {
				markDirectoryChange(activity)
			}
			if activity.Path == "" || nativeExcluded(c, activity.Path) || !nativeInScope(activity.Path, c.Security.NativeFIM.Paths) {
				continue
			}
			if err := nativeAccumulate(bursts, activity); err != nil {
				health(err)
				flushReady(true)
				if retryErr := nativeAccumulate(bursts, activity); retryErr != nil {
					health(retryErr)
				}
			}
		case <-flush.C:
			flushReady(false)
			if !directoryFirst.IsZero() && (time.Since(directoryLast) >= 200*time.Millisecond || time.Since(directoryFirst) >= 2*time.Second) {
				err := reconcile()
				health(err)
				if err == nil {
					directoryFirst, directoryLast = time.Time{}, time.Time{}
				} else {
					// Retry transient read/backpressure failures without a busy loop.
					directoryFirst, directoryLast = time.Now(), time.Now()
				}
			}
		case <-ticker.C:
			flushReady(false)
			health(reconcile())
		}
	}
}
