package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sshTestConfig(t *testing.T, source string) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{StateFile: filepath.Join(dir, "state.json"), location: time.UTC,
		Login: LoginConfig{Enabled: true, Source: source, Path: filepath.Join(dir, "auth.log"), MaxRecords: 1000, TimeoutSeconds: 10, InitialLookbackHours: 24}}
}

func saveLoginState(t *testing.T, c Config, s *loginBaseline) {
	t.Helper()
	if s == nil {
		t.Fatal("missing login state")
	}
	if err := writeState(c.StateFile+".logins", "login", s); err != nil {
		t.Fatal(err)
	}
}

func loginJSON(user, id string, at time.Time) string {
	b, _ := json.Marshal(LoginRecord{ID: id, User: user, SourceIP: "192.0.2.4", Terminal: "N/A", LoginTime: at})
	return string(b) + "\n"
}

func TestSSHJSONLAllRecordsAcrossPollsAndRestart(t *testing.T) {
	c := sshTestConfig(t, "jsonl")
	now := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	first := loginJSON("first", "", now)
	put(t, c.Login.Path, first)
	r, s, issues := collectSSHLogins(c, now)
	if len(issues) != 0 || !r.Success || len(r.Records) != 1 {
		t.Fatalf("first scan: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	// Same timestamp, and even an identical record twice, are separate logins.
	second := loginJSON("second", "", now)
	put(t, c.Login.Path, first+second+second)
	r, s, issues = collectSSHLogins(c, now.Add(time.Minute))
	if len(issues) != 0 || len(r.Records) != 2 || r.Records[0].ID == r.Records[1].ID {
		t.Fatalf("two new logins: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	// A fresh collector has no in-memory cursor and still does not repeat.
	r, _, issues = collectSSHLogins(c, now.Add(2*time.Minute))
	if len(issues) != 0 || len(r.Records) != 0 || r.Record == nil || r.Record.User != "second" {
		t.Fatalf("restart: %+v %v", r, issues)
	}
}

func TestSSHJSONLPageLimitNeverDropsPendingLogins(t *testing.T) {
	c := sshTestConfig(t, "jsonl")
	c.Login.MaxRecords = 1
	now := time.Now().UTC()
	put(t, c.Login.Path, loginJSON("one", "", now)+loginJSON("two", "", now)+loginJSON("three", "", now))
	for i, user := range []string{"one", "two", "three"} {
		r, s, issues := collectSSHLogins(c, now)
		if len(issues) != 0 || len(r.Records) != 1 || r.Records[0].User != user || r.Pending != (i < 2) {
			t.Fatalf("page %d: %+v %v", i, r, issues)
		}
		saveLoginState(t, c, s)
	}
}

func TestSSHFailureDoesNotAdvanceDurableState(t *testing.T) {
	c := sshTestConfig(t, "jsonl")
	now := time.Now().UTC()
	valid := loginJSON("one", "", now)
	put(t, c.Login.Path, valid)
	_, s, _ := collectSSHLogins(c, now)
	saveLoginState(t, c, s)
	before := read(t, c.StateFile+".logins")
	put(t, c.Login.Path, valid+loginJSON("two", "", now)+"{broken\n")
	r, s, issues := collectSSHLogins(c, now)
	if r.Success || s != nil || len(issues) == 0 || len(r.Records) != 0 {
		t.Fatalf("failed collection committed: %+v %v", r, issues)
	}
	if read(t, c.StateFile+".logins") != before {
		t.Fatal("failed collection changed durable cursor")
	}
	put(t, c.Login.Path, valid+loginJSON("two", "", now))
	r, _, issues = collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 1 || r.Records[0].User != "two" {
		t.Fatalf("recovery lost login: %+v %v", r, issues)
	}
}

func journalLine(cursor, message string, now time.Time) string {
	b, _ := json.Marshal(journalLoginEntry{Cursor: cursor, Timestamp: fmt.Sprint(now.UnixMicro()), Message: message})
	return string(b) + "\n"
}

func TestSSHJournalPagesPreserveEveryCursorAndTimestamp(t *testing.T) {
	now := time.Now().UTC()
	s := &loginBaseline{}
	page := journalLine("cursor1", "Accepted publickey for ops from 192.0.2.10 port 42000 ssh2: ED25519 SHA256:test", now) +
		journalLine("cursor2", "Accepted password for root from 2001:db8::1 port 42001 ssh2", now) +
		journalLine("cursor3", "Disconnected from user ops", now)
	records, pending, err := parseJournalPage(strings.NewReader(page), 2, s)
	if err != nil || !pending || len(records) != 2 || s.JournalCursor != "cursor2" {
		t.Fatalf("journal page: %+v %v %v", records, pending, err)
	}
	if records[0].Terminal != "N/A" || records[0].Method != "publickey" || records[1].SourceIP != "2001:db8::1" || records[0].ID == records[1].ID {
		t.Fatalf("SSH records: %+v", records)
	}
	if records[0].LoginTime.UnixMicro() != now.UnixMicro() {
		t.Fatal("journal timestamp changed")
	}
	args := strings.Join(journalArgs(LoginConfig{}, s), " ")
	if !strings.Contains(args, "--after-cursor=cursor2") || strings.Contains(args, "--since") || !strings.Contains(args, "sshd-session") {
		t.Fatalf("journal resume args: %s", args)
	}
	records, pending, err = parseJournalPage(strings.NewReader(journalLine("cursor3", "Disconnected from user ops", now)), 2, s)
	if err != nil || pending || len(records) != 0 || s.JournalCursor != "cursor3" {
		t.Fatalf("non-login cursor: %v %v %v", records, pending, err)
	}
}

func TestSSHJournalInitialWindowAndMalformedEntry(t *testing.T) {
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := &loginBaseline{Since: since}
	args := strings.Join(journalArgs(LoginConfig{}, s), " ")
	if !strings.Contains(args, fmt.Sprintf("--since=@%d", since.Unix())) || strings.Contains(args, "--lines") {
		t.Fatalf("unbounded tail/incorrect initial window: %s", args)
	}
	for _, input := range []string{`{"MESSAGE":"accepted"}`, `not-json`, `{"__CURSOR":"cursor","__REALTIME_TIMESTAMP":"bad"}`} {
		if _, _, err := parseJournalPage(strings.NewReader(input), 5, s); err == nil {
			t.Fatalf("accepted corrupt journal entry: %s", input)
		}
	}
}

func authLine(user string, now time.Time) string {
	return now.Format(time.RFC3339Nano) + " host sshd[1200]: Accepted publickey for " + user + " from 192.0.2.8 port 42000 ssh2\n"
}

func TestSSHAuthlogIncrementalAppendAndRotation(t *testing.T) {
	c := sshTestConfig(t, "authlog")
	now := time.Now().UTC().Truncate(time.Second)
	initial := authLine("one", now)
	put(t, c.Login.Path, initial)
	r, s, issues := collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 1 {
		t.Fatalf("initial auth log: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	// An unread successful login remains in the rotated file.
	put(t, c.Login.Path, initial+authLine("two", now))
	if err := os.Rename(c.Login.Path, c.Login.Path+".1"); err != nil {
		t.Fatal(err)
	}
	put(t, c.Login.Path, authLine("three", now))
	r, s, issues = collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 2 || r.Records[0].User != "two" || r.Records[1].User != "three" {
		t.Fatalf("rotated auth log: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	r, _, issues = collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 0 {
		t.Fatalf("auth log repeated: %+v %v", r, issues)
	}
}

func TestSSHAuthlogLimitAndIncompleteTail(t *testing.T) {
	c := sshTestConfig(t, "authlog")
	c.Login.MaxRecords = 1
	now := time.Now().UTC()
	initial := authLine("one", now)
	partial := strings.TrimSuffix(authLine("two", now), "\n")
	put(t, c.Login.Path, initial+partial)
	r, s, issues := collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 1 || !r.Pending {
		t.Fatalf("first auth page: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	r, s, issues = collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 0 || s.Auth.Offset != int64(len(initial)) {
		t.Fatalf("consumed incomplete tail: %+v %v", r, issues)
	}
	saveLoginState(t, c, s)
	put(t, c.Login.Path, initial+partial+"\n")
	r, _, issues = collectSSHLogins(c, now)
	if len(issues) != 0 || len(r.Records) != 1 || r.Records[0].User != "two" {
		t.Fatalf("lost completed tail: %+v %v", r, issues)
	}
}

func TestSSHAuthlogMissingRotationReportsGap(t *testing.T) {
	c := sshTestConfig(t, "authlog")
	now := time.Now().UTC()
	put(t, c.Login.Path, authLine("one", now))
	_, s, _ := collectSSHLogins(c, now)
	saveLoginState(t, c, s)
	put(t, c.Login.Path, authLine("replacement", now))
	r, s, issues := collectSSHLogins(c, now)
	if r.Success || s != nil || len(issues) == 0 || !strings.Contains(issues[0].Message, "possible login gap") {
		t.Fatalf("silent log gap: %+v %v", r, issues)
	}
}

func TestSSHAuthlogClassicSyslogYearBoundaryAndTerminal(t *testing.T) {
	now := time.Date(2027, 1, 1, 1, 0, 0, 0, time.Local)
	r, err := parseAuthLine("Dec 31 23:59:59 host sshd-session[1]: Accepted password for root from 2001:db8::1 port 12 ssh2 on pts/3\n", now, "event1")
	if err != nil || r == nil || r.LoginTime.Year() != 2026 || r.Terminal != "pts/3" {
		t.Fatalf("classic syslog: %+v %v", r, err)
	}
	r, err = parseAuthLine("Jan  1 00:01:00 host unrelated[1]: Accepted password for root from 192.0.2.1 port 12 ssh2", now, "event2")
	if err != nil || r != nil {
		t.Fatalf("non-SSH log accepted: %+v %v", r, err)
	}
}

func TestSSHLastRecordsRetainsAllLogins(t *testing.T) {
	output := "root pts/1 192.0.2.1 2026-10-02T03:00:00+00:00 still logged in\nops pts/2 192.0.2.2 2026-10-02T03:00:00+00:00 still logged in\nreboot system boot 2026-10-02T00:00:00+00:00\nwtmp begins 2026-10-01T00:00:00+00:00\n"
	records, err := parseLastRecords(output)
	if err != nil || len(records) != 2 {
		t.Fatalf("wtmp logins: %+v %v", records, err)
	}
}

func TestSSHRejectsCorruptCursorWithoutPanic(t *testing.T) {
	c := sshTestConfig(t, "authlog")
	now := time.Now().UTC()
	put(t, c.Login.Path, authLine("one", now))
	_, s, _ := collectSSHLogins(c, now)
	s.Auth.PrefixBytes = -1
	saveLoginState(t, c, s)
	r, next, issues := collectSSHLogins(c, now)
	if r.Success || next != nil || len(issues) == 0 || !strings.Contains(issues[0].Message, "invalid SSH auth log cursor") {
		t.Fatalf("invalid persisted cursor: %+v %v", r, issues)
	}
}
