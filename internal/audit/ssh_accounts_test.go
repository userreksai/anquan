package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/security"
)

func accountSource(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSSHAccountsReportsLocalMetadataWithoutCredentials(t *testing.T) {
	source := accountSource(t, "# ignored\n+::::::\nnobody:SECRET_HASH:65534:65534:PRIVATE_COMMENT:/PRIVATE_HOME:/usr/sbin/nologin\nops:x:1001:1001::/home/ops:/bin/bash\nroot:x:0:0::/root:/bin/bash\nempty:x:1002:1002::/home/empty:\n")
	at := time.Now().UTC()
	got := readSSHAccounts(source, at)
	if got.State != "ready" || got.Total != 4 || got.Truncated || got.Source != "/etc/passwd" || !got.CheckedAt.Equal(at) {
		t.Fatalf("unexpected account snapshot: %+v", got)
	}
	if got.Users[0].Name != "root" || got.Users[1].Name != "ops" || !got.Users[2].LoginShell || got.Users[3].LoginShell {
		t.Fatalf("login shell classification or ordering wrong: %+v", got.Users)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET_HASH", "PRIVATE_COMMENT", "PRIVATE_HOME", "/home/ops", "/root"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("private passwd field was transmitted: %q", secret)
		}
	}
	// Each sample rereads the source; a service restart is unnecessary.
	if err := os.WriteFile(source, []byte("newuser:x:1200:1200::/home/newuser:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	next := readSSHAccounts(source, at.Add(30*time.Second))
	if next.Total != 1 || next.Users[0].Name != "newuser" {
		t.Fatalf("account changes were not discovered: %+v", next)
	}
}

func TestSSHAccountsBoundsTheCompleteSerializedInventory(t *testing.T) {
	for _, shell := range []string{"/bin/bash", "/" + strings.Repeat("s", 255)} {
		var source strings.Builder
		for i := range 600 {
			fmt.Fprintf(&source, "user%04d:x:%d:%d::/home/private:%s\n", i, i+1000, i+1000, shell)
		}
		got := readSSHAccounts(accountSource(t, source.String()), time.Now())
		raw, err := json.Marshal(got)
		if err != nil || got.State != "ready" || got.Total != 600 || !got.Truncated ||
			len(got.Users) == 0 || len(got.Users) > maxSSHAccountUsers || len(raw) > maxSSHAccountInventoryBytes {
			t.Fatalf("account count/byte budget lost: users=%d bytes=%d snapshot=%+v err=%v", len(got.Users), len(raw), got, err)
		}
	}
}

func TestSSHAccountsRejectsIncompleteOrMalformedSources(t *testing.T) {
	for _, source := range []string{
		"ops:x:1000:1000::/home/ops:/bin/bash\nbroken\n",
		"ops:x:1000:1000::/home/ops:/bin/bash\nops:x:1001:1001::/home/other:/bin/sh\n",
		"ops:x:4294967296:1000::/home/ops:/bin/bash\n",
		"ops:x:1000:1000::/home/ops:/bin/ba\tsh\n",
		"123ops:x:1000:1000::/home/ops:/bin/bash\n",
		strings.Repeat("#"+strings.Repeat("x", 1022)+"\n", maxSSHAccountSourceBytes/1024+1),
	} {
		got := readSSHAccounts(accountSource(t, source), time.Now())
		if got.State != "error" || len(got.Users) != 0 || got.Total != 0 || got.Truncated || got.Error == "" {
			t.Fatalf("unsafe partial snapshot accepted: %+v", got)
		}
	}
	got := readSSHAccounts(filepath.Join(t.TempDir(), "missing"), time.Now())
	if got.State != "error" || len(got.Users) != 0 {
		t.Fatalf("missing source reported as an empty ready list: %+v", got)
	}
}

func TestSSHAccountChangesAreReportedWithoutTimestampNoise(t *testing.T) {
	at := time.Now().UTC()
	inventory := sshAccountInventory{State: "ready", Source: "/etc/passwd", CheckedAt: at, Total: 1, Users: []sshAccount{{Name: "ops", UID: 1000, GID: 1000, Shell: "/bin/bash", LoginShell: true}}}
	var reporter componentStatusReporter
	var sent []security.Event
	emit := func(delta time.Duration) {
		t.Helper()
		event := reportingStatus(at.Add(delta), "running", 0)
		event.Data["inventory"] = map[string]any{"ssh_accounts": inventory}
		if err := reporter.emit(event, func(event security.Event) error { sent = append(sent, event); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	emit(0)
	inventory.CheckedAt = at.Add(30 * time.Second)
	emit(30 * time.Second)
	if len(sent) != 1 {
		t.Fatal("account sample time generated repeated status traffic")
	}
	inventory.Users = append(inventory.Users, sshAccount{Name: "deploy", UID: 1001, GID: 1001, Shell: "/bin/sh", LoginShell: true})
	inventory.Total++
	emit(time.Minute)
	if len(sent) != 2 || sent[1].Data["snapshot_only"] == true {
		t.Fatal("added account was delayed until the periodic snapshot")
	}
	inventory.Users = inventory.Users[1:]
	inventory.Total--
	emit(90 * time.Second)
	if len(sent) != 3 {
		t.Fatal("removed account was not reported")
	}
	inventory.Users[0].Shell, inventory.Users[0].LoginShell = "/bin/false", false
	emit(2 * time.Minute)
	if len(sent) != 4 {
		t.Fatal("account shell change was not reported")
	}
}

func TestSSHAccountInventorySurvivesLargePolicyStatus(t *testing.T) {
	var source strings.Builder
	for i := range 600 {
		fmt.Fprintf(&source, "user%04d:x:%d:%d::/home/private:/%s\n", i, i+1000, i+1000, strings.Repeat("s", 255))
	}
	inventory := readSSHAccounts(accountSource(t, source.String()), time.Now())
	data := map[string]any{"inventory": map[string]any{"ssh_accounts": inventory}}
	checks := make([]any, 80)
	for i := range checks {
		checks[i] = map[string]any{"setting": "sudo.grant.ops", "actual": strings.Repeat("\x00", 32768)}
	}
	boundSecurityStatus(data, []map[string]any{{"name": "policies", "state": "drift", "checks": checks}})
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > 48000 || !strings.Contains(string(raw), "user0000") {
		t.Fatalf("inventory broke status transport or was dropped: bytes=%d err=%v", len(raw), err)
	}
	c := securityTestConfig(t)
	q, err := openSecurityQueue(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.enqueue(c, security.Event{Type: "component_status", Data: data}); err != nil {
		t.Fatal(err)
	}
}
