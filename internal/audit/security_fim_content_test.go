package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"anqu/internal/security"
)

func nativeFIMTestRoot(t *testing.T) (Config, string) {
	t.Helper()
	c := securityTestConfig(t)
	root := filepath.Join(t.TempDir(), "watched")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	c.Security.NativeFIM.Paths = []string{root}
	return c, root
}

func nativeFIMDetails(t *testing.T, e security.Event) map[string]any {
	t.Helper()
	d, ok := e.Data["details"].(map[string]any)
	if !ok {
		t.Fatalf("missing details: %+v", e)
	}
	return d
}

func TestNativeFIMCreatedContentLifecycleAndRestart(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	old := filepath.Join(root, "existing.conf")
	os.WriteFile(old, []byte("EXISTING_PRIVATE_VALUE"), 0600)
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatal("new root emitted its existing contents")
	}
	_, state, unlock, err := nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := state.Files[old]; n.Text != "" || n.ContentTracked {
		t.Fatalf("existing file captured: %+v", n)
	}
	unlock()
	p := filepath.Join(root, "123.sh")
	first := "#!/bin/sh\necho original\n"
	os.WriteFile(p, []byte(first), 0700)
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("creation count: %d", len(events))
	}
	d := nativeFIMDetails(t, events[0])
	if d["change"] != "added" || d["current_text"] != first || d["current_content_status"] != "captured" || d["previous_content_status"] != "not_applicable" {
		t.Fatalf("creation: %+v", d)
	}
	second := "#!/bin/sh\necho modified\n"
	os.WriteFile(p, []byte(second), 0700)
	if err := pollNativeFIM(context.Background(), NewSession(c), emit); err != nil {
		t.Fatal(err)
	}
	d = nativeFIMDetails(t, events[1])
	if d["change"] != "modified" || d["previous_text"] != first || d["current_text"] != second {
		t.Fatalf("modification: %+v", d)
	}
	os.Remove(p)
	if err := pollNativeFIM(context.Background(), NewSession(c), emit); err != nil {
		t.Fatal(err)
	}
	d = nativeFIMDetails(t, events[2])
	if d["change"] != "deleted" || d["previous_text"] != second || d["current_content_status"] != "not_applicable" {
		t.Fatalf("deletion: %+v", d)
	}
	if len(events) != 3 {
		t.Fatalf("unexpected duplicate: %+v", events)
	}
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatal("unchanged restart repeated notification")
	}
}

func TestNativeFIMCaptureDisabledAndPolicyChangeIsSilent(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	no := false
	c.Security.NativeFIM.CaptureCreatedContent = &no
	emit := func(security.Event) error { return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "file.txt")
	os.WriteFile(p, []byte("do not capture"), 0600)
	var events []security.Event
	emit = func(e security.Event) error { events = append(events, e); return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	d := nativeFIMDetails(t, events[0])
	if d["current_content_status"] != "disabled" {
		t.Fatalf("disabled: %+v", d)
	}
	if _, exists := d["current_text"]; exists {
		t.Fatal("explicit false exposed content")
	}
	yes := true
	c.Security.NativeFIM.CaptureCreatedContent = &yes
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatal("enabling capture emitted fake modification")
	}
	c.Security.NativeFIM.ReportChanges = true
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatal("hydrating text emitted fake modification")
	}
	c.Security.NativeFIM.ReportChanges = false
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatal("scrubbing text emitted fake modification")
	}
	_, state, unlock, err := nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if state.Files[p].Text != "" {
		t.Fatal("explicitly untracked preexisting content retained")
	}
}

func TestNativeFIMContentBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, text, status string }{
		{"empty.txt", "", "empty"},
		{"text.sh", "#!/bin/sh\necho hello", "captured"},
		{"nul.bin", "a\x00b", "binary"},
		{"invalid.bin", "\xff\xfe", "binary"},
		{"invalid-tail.bin", strings.Repeat("a", 1024) + "\xff", "binary"},
		{"secret.sh", "NEVER_STORE_SECRET", "sensitive"},
		{"long.txt", strings.Repeat("中文", 200), "truncated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(p, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			n, err := nativeReadFile(context.Background(), p, &NativeFIMConfig{MaxDiffBytes: 256}, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if n.ContentStatus != tc.status || len(n.Text) > 256 || !utf8.ValidString(n.Text) {
				t.Fatalf("capture: %+v", n)
			}
			if tc.status == "binary" || tc.status == "sensitive" {
				if n.Text != "" {
					t.Fatal("unsafe plaintext retained")
				}
			}
			if tc.status == "truncated" && (!n.TextTruncated || !strings.HasPrefix(tc.text, n.Text) || n.Text == "") {
				t.Fatal("prefix lost")
			}
		})
	}
}

func TestNativeFIMReservedOldContentRespectsChangedPolicy(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	c.Security.NativeFIM.ReportChanges = true
	p := filepath.Join(root, "existing.txt")
	os.WriteFile(p, []byte("old existing text"), 0600)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("changed existing text"), 0600)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return errors.New("offline") }); err == nil {
		t.Fatal("did not reserve pending event")
	}
	c.Security.NativeFIM.ReportChanges = false
	var replay []security.Event
	if err := pollNativeFIM(context.Background(), NewSession(c), func(e security.Event) error { replay = append(replay, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(replay) != 1 {
		t.Fatalf("policy caused extra changes: %d", len(replay))
	}
	d := nativeFIMDetails(t, replay[0])
	for _, prefix := range []string{"previous", "current"} {
		if _, exists := d[prefix+"_text"]; exists || d[prefix+"_content_status"] != "disabled" {
			t.Fatalf("reserved text exposed: %+v", d)
		}
	}
}

func TestNativeFIMReservedTextHonorsReducedContentLimit(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "tracked.txt")
	os.WriteFile(p, []byte(strings.Repeat("中文", 1000)), 0600)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return errors.New("offline") }); err == nil {
		t.Fatal("pending event not reserved")
	}
	c.Security.NativeFIM.MaxDiffBytes = 256
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error {
		d := nativeFIMDetails(t, e)
		text, ok := d["current_text"].(string)
		if !ok || len(text) > 256 || !utf8.ValidString(text) || d["current_content_status"] != "truncated" {
			t.Fatalf("old limit survived replay: %+v", d)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFIMUnknownHashDoesNotInventModification(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "tracked.txt")
	os.WriteFile(p, []byte("reliable contents"), 0600)
	emit := func(security.Event) error { return nil }
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	_, state, unlock, err := nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	known := state.Files[p]
	unlock()
	unknown := known
	unknown.SHA256, unknown.Text, unknown.ContentStatus = "", "", "unavailable"
	accepted, err := nativeApplyObservations(c, []nativeFIMObservation{{Path: p, After: &unknown, Observed: true}}, func(e security.Event) error { t.Fatalf("read failure invented event: %+v", e); return nil })
	if !accepted || err != nil {
		t.Fatalf("transient observation: %v %v", accepted, err)
	}
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error { t.Fatalf("recovery invented event: %+v", e); return nil }); err != nil {
		t.Fatal(err)
	}
	_, state, unlock, err = nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if state.Files[p].Text != known.Text || state.Files[p].SHA256 != known.SHA256 {
		t.Fatal("transient read discarded last reliable content")
	}
}

func TestNativeFIMExactRootDeletionDoesNotRepeatAsMissing(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	p := filepath.Join(root, "exact.sh")
	os.WriteFile(p, []byte("original"), 0700)
	c.Security.NativeFIM.Paths = []string{p}
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.Remove(p)
	var events []security.Event
	emit := func(e security.Event) error { events = append(events, e); return nil }
	accepted, err := nativeApplyObservations(c, []nativeFIMObservation{{Path: p, Observed: true}}, emit)
	if !accepted || err != nil {
		t.Fatalf("delete: %v %v", accepted, err)
	}
	for i := 0; i < 2; i++ {
		if err := pollNativeFIM(context.Background(), c, emit); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 1 || nativeFIMDetails(t, events[0])["change"] != "deleted" {
		t.Fatalf("duplicate deletion: %+v", events)
	}
	os.WriteFile(p, []byte("recreated"), 0700)
	if err := pollNativeFIM(context.Background(), c, emit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || nativeFIMDetails(t, events[1])["change"] != "added" {
		t.Fatalf("recreation: %+v", events)
	}
}

func TestNativeFIMOversizedReadIsBoundedAndExplicit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "large.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(nativeHashLimit + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	n, err := nativeReadFile(context.Background(), p, &NativeFIMConfig{MaxDiffBytes: 256}, true, true)
	if err != nil || n.ContentStatus != "unavailable" || n.Text != "" || n.SHA256 != "" {
		t.Fatalf("oversized: %+v %v", n, err)
	}
}

func TestNativeFIMUTF8StreamingBoundaries(t *testing.T) {
	for _, text := range []string{"hello", "中文🛠️", strings.Repeat("x", 255) + "中文"} {
		for _, chunk := range []int{1, 2, 3, 4, 7, 32} {
			var validation nativeUTF8Stream
			for pos := 0; pos < len(text); pos += chunk {
				end := pos + chunk
				if end > len(text) {
					end = len(text)
				}
				validation.write([]byte(text[pos:end]))
			}
			if validation.invalid || len(validation.tail) != 0 {
				t.Fatalf("valid UTF8 rejected with chunk %d", chunk)
			}
		}
	}
	for _, text := range []string{"x\xff", "\xe4\xb8", "\xc0\x80", "\xed\xa0\x80"} {
		var validation nativeUTF8Stream
		for i := range text {
			validation.write([]byte{text[i]})
		}
		if !validation.invalid && len(validation.tail) == 0 {
			t.Fatalf("invalid UTF8 accepted: %q", text)
		}
	}
}

func TestNativeFIMTransportRetainsBoundedUTF8Prefix(t *testing.T) {
	// Control characters expand sixfold in JSON; byte limits must be applied
	// after serialization, while retaining a visible prefix and its status.
	text := strings.Repeat("\x01中", 4096)
	details := map[string]any{"previous_text": text, "current_text": text, "previous_content_status": "captured", "current_content_status": "captured"}
	e := security.Event{Data: map[string]any{"source": "native_fim", "details": details}}
	if err := nativeBoundEvent(&e); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e.Data)
	if err != nil || len(b) > 48000 {
		t.Fatalf("transport: bytes=%d err=%v", len(b), err)
	}
	for _, prefix := range []string{"previous", "current"} {
		got, ok := details[prefix+"_text"].(string)
		if !ok || got == "" || !strings.HasPrefix(text, got) || !utf8.ValidString(got) {
			t.Fatal("capture discarded or invalid")
		}
		if len(got) < len(text) && (details[prefix+"_content_status"] != "truncated" || details[prefix+"_text_truncated"] != true) {
			t.Fatal("truncation unmarked")
		}
	}
}

func TestNativeFIMObservedBurstRetainsTransitionsAcrossQueueFailure(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "quick.sh")
	when := time.Now()
	a := nativeFile{Type: "file", SHA256: "one", Size: 4, Text: "one\n", ContentStatus: "captured"}
	b := nativeFile{Type: "file", SHA256: "two", Size: 4, Text: "two\n", ContentStatus: "captured"}
	bursts := map[string]*nativeFIMBurst{}
	for _, event := range []nativeWatchEvent{
		{Path: p, Mask: nativeCreate, Snapshot: &a, At: when},
		{Path: p, Mask: nativeModify, Snapshot: &a, At: when},
		{Path: p, Mask: nativeCloseWrite, Snapshot: &b, At: when},
		{Path: p, Mask: nativeDelete, At: when},
	} {
		if err := nativeAccumulate(bursts, event); err != nil {
			t.Fatal(err)
		}
	}
	if len(bursts[p].Stages) != 2 || bursts[p].Stages[0].After.Text != "two\n" {
		t.Fatalf("burst: %+v", bursts[p])
	}
	var firstID string
	accepted, err := nativeApplyObservations(c, bursts[p].Stages, func(e security.Event) error { firstID = e.ID; return errors.New("outbox full") })
	if !accepted || err == nil || firstID == "" {
		t.Fatalf("batch durability: %v %v", accepted, err)
	}
	var received []security.Event
	if err := pollNativeFIM(context.Background(), NewSession(c), func(e security.Event) error { received = append(received, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 || received[0].ID != firstID || received[0].ID == received[1].ID {
		t.Fatalf("replay: %+v", received)
	}
	if d := nativeFIMDetails(t, received[0]); d["change"] != "added" || d["current_text"] != "two\n" {
		t.Fatalf("creation lost: %+v", d)
	}
	if d := nativeFIMDetails(t, received[1]); d["change"] != "deleted" || d["previous_text"] != "two\n" {
		t.Fatalf("deletion lost: %+v", d)
	}
}

func TestNativeFIMInstantRemovalReportsUncapturedContent(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "vanished.sh")
	bursts := map[string]*nativeFIMBurst{}
	for _, mask := range []uint32{nativeCreate, nativeCloseWrite, nativeDelete} {
		if err := nativeAccumulate(bursts, nativeWatchEvent{Path: p, Mask: mask}); err != nil {
			t.Fatal(err)
		}
	}
	var events []security.Event
	accepted, err := nativeApplyObservations(c, bursts[p].Stages, func(e security.Event) error { events = append(events, e); return nil })
	if !accepted || err != nil || len(events) != 2 {
		t.Fatalf("short lifecycle: accepted=%v err=%v events=%+v", accepted, err, events)
	}
	if d := nativeFIMDetails(t, events[0]); d["current_content_status"] != "unavailable" {
		t.Fatalf("misleading creation: %+v", d)
	}
	if d := nativeFIMDetails(t, events[1]); d["previous_content_status"] != "unavailable" {
		t.Fatalf("misleading deletion: %+v", d)
	}
}

func TestNativeFIMEditorArtifactsAndOldStateAreSilent(t *testing.T) {
	c, root := nativeFIMTestRoot(t)
	for _, name := range []string{".123.sh.swp", ".123.sh.swo", ".123.sh.swx", "4913", ".#123.sh", "#123.sh#", "123.sh~"} {
		p := filepath.Join(root, name)
		if !nativeExcluded(c, p) {
			t.Fatalf("editor artifact not excluded: %s", name)
		}
	}
	for _, name := range []string{".env", ".hidden.sh", "normal.tmp", "swap.swp"} {
		if nativeExcluded(c, filepath.Join(root, name)) {
			t.Fatalf("ordinary file ignored: %s", name)
		}
	}
	p := filepath.Join(root, ".123.sh.swp")
	c.Security.NativeFIM.Paths = append(c.Security.NativeFIM.Paths, p)
	if nativeExcluded(c, p) {
		t.Fatal("explicit monitored file ignored")
	}
	c.Security.NativeFIM.Paths = []string{root}
	if err := pollNativeFIM(context.Background(), c, func(security.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	statePath, state, unlock, err := nativeLoadState(c)
	if err != nil {
		t.Fatal(err)
	}
	state.Files[p] = nativeFile{Type: "file", SHA256: "legacy"}
	err = writeState(statePath, "security-fim", state)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := pollNativeFIM(context.Background(), c, func(e security.Event) error { t.Fatalf("legacy temporary state produced event: %+v", e); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFIMCaptureFlagDefaultsAndExplicitFalse(t *testing.T) {
	for _, tc := range []struct {
		suffix  string
		enabled bool
	}{{"", true}, {", capture_created_content: false", false}, {", capture_created_content: true", true}} {
		text := "output_dir: output\nserver: ['127.0.0.1:55555']\nlogin: {enabled: false}\nsetup: {logs: logs/a.log, prom: metrics/a.prom}\nsecurity:\n  enabled: true\n  native_fim: {enabled: true, paths: [watched]" + tc.suffix + "}\n"
		c, err := ParseConfig([]byte(text), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if c.Security.NativeFIM.CaptureCreatedContent == nil || *c.Security.NativeFIM.CaptureCreatedContent != tc.enabled || c.Security.NativeFIM.ReportChanges {
			t.Fatalf("flag default/explicit false changed: %+v", c.Security.NativeFIM)
		}
	}
}
