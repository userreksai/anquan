package audit

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func decodeUDPEvents(t *testing.T, c Config, r Report, ip string) []udpEnvelope {
	t.Helper()
	messages, err := udpMessages(c, r, ip)
	if err != nil {
		t.Fatal(err)
	}
	events := make([]udpEnvelope, len(messages))
	for i, message := range messages {
		if err := json.Unmarshal(message, &events[i]); err != nil {
			t.Fatal(err)
		}
	}
	return events
}

func TestUDPProtocolKeepsFindingEvidenceAndLoginOccurrence(t *testing.T) {
	start := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	loginTime := start.Add(-time.Hour)
	r := Report{Host: "node-a", StartedAt: start, FinishedAt: start.Add(time.Second), Success: true,
		Alerts: []Alert{{Module: "files", Kind: "modified", Target: "/etc/ssh/sshd_config", Before: "900150983cd24fb0d6963f7d28e17f72", After: "d41d8cd98f00b204e9800998ecf8427e", Message: "file changed"}},
		Login: LoginResult{Pending: true, Records: []LoginRecord{
			{ID: "journal:cursor-1", User: "root", SourceIP: "192.0.2.8", LoginTime: loginTime, Terminal: "N/A", Method: "publickey"},
			{ID: "journal:cursor-2", User: "root", SourceIP: "192.0.2.8", LoginTime: loginTime, Terminal: "N/A", Method: "publickey"},
		}},
	}
	c := Config{Setup: &SetupConfig{IntervalSeconds: 60}}
	events := decodeUDPEvents(t, c, r, "192.0.2.20")
	if len(events) != 4 {
		t.Fatal(events)
	}
	for _, event := range events {
		if event.Version != 1 || event.IP != "192.0.2.20" || event.Host != r.Host || len(event.EventID) != 64 {
			t.Fatalf("invalid envelope: %+v", event)
		}
	}
	var summary struct {
		IntervalSeconds int       `json:"interval_seconds"`
		Logins          int       `json:"logins"`
		LoginPending    bool      `json:"login_pending"`
		FinishedAt      time.Time `json:"finished_at"`
	}
	if err := json.Unmarshal(events[0].Data, &summary); err != nil {
		t.Fatal(err)
	}
	if events[0].Type != "scan_summary" || summary.IntervalSeconds != 60 || summary.Logins != 2 || !summary.LoginPending || !summary.FinishedAt.Equal(r.FinishedAt) {
		t.Fatalf("heartbeat incomplete: %+v %+v", events[0], summary)
	}
	var alert Alert
	if err := json.Unmarshal(events[1].Data, &alert); err != nil || alert != r.Alerts[0] {
		t.Fatalf("file evidence lost: %+v %v", alert, err)
	}
	var login LoginRecord
	if err := json.Unmarshal(events[2].Data, &login); err != nil || !reflect.DeepEqual(login, r.Login.Records[0]) {
		t.Fatalf("login evidence lost: %+v %v", login, err)
	}
	if !events[2].Time.Equal(loginTime) || events[2].EventID == events[3].EventID {
		t.Fatal("login must retain its occurrence time and distinguish identical separate sessions")
	}
	// Replaying the report is idempotent, including repeated UDP submissions.
	if replay := decodeUDPEvents(t, c, r, "192.0.2.20"); !reflect.DeepEqual(events, replay) {
		t.Fatal("same report produced different IDs")
	}
	// A failed local publication can cause the durable login cursor to be read
	// again by a later scan. It must not create a second login in the master.
	r.StartedAt = start.Add(5 * time.Minute)
	r.FinishedAt = r.StartedAt.Add(time.Second)
	retry := decodeUDPEvents(t, c, r, "192.0.2.20")
	if events[2].EventID != retry[2].EventID || events[3].EventID != retry[3].EventID {
		t.Fatal("same login changed identity across scans")
	}
	if events[0].EventID == retry[0].EventID || events[1].EventID == retry[1].EventID {
		t.Fatal("later scan observations must remain separate")
	}
	otherMachine := decodeUDPEvents(t, c, r, "192.0.2.21")
	if retry[2].EventID == otherMachine[2].EventID {
		t.Fatal("machines with identical hostnames must have distinct events")
	}
}

func TestUDPLoginWithoutRecordIDIsStableAcrossScans(t *testing.T) {
	at := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	r := Report{Host: "node", StartedAt: at, Login: LoginResult{Records: []LoginRecord{{User: "ops", LoginTime: at.Add(-time.Hour), SourceIP: "192.0.2.1", Terminal: "pts/1"}}}}
	first := decodeUDPEvents(t, Config{}, r, "192.0.2.2")
	r.StartedAt = at.Add(time.Minute)
	second := decodeUDPEvents(t, Config{}, r, "192.0.2.2")
	if first[1].EventID != second[1].EventID {
		t.Fatal("legacy login without a source ID changed identity across scans")
	}
}

func TestUDPReportsExplicitMachineIPBehindNAT(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := Config{Server: []string{listener.LocalAddr().String()}, AgentIP: "10.20.30.40"}
	result := notifyServers(c, Report{Host: "nat-node", StartedAt: time.Now(), Success: true})
	if len(result) != 1 || result[0].Error != "" || result[0].IP != c.AgentIP || result[0].Sent != 1 {
		t.Fatalf("notification failed: %+v", result)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65536)
	n, _, err := listener.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	var event udpEnvelope
	if err := json.Unmarshal(b[:n], &event); err != nil || event.IP != c.AgentIP || event.Type != "scan_summary" {
		t.Fatalf("wrong machine identity: %s %v", b[:n], err)
	}
}

func TestAgentIPValidation(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "example.com", "192.0.2.1:55555", "192.0.2.999"} {
		data := "server: []\nagent_ip: '" + ip + "'\n"
		if err := ValidateEmbeddedYAML([]byte(data), "linux"); err == nil || !strings.Contains(err.Error(), "agent_ip") {
			t.Fatalf("invalid identity accepted: %q %v", ip, err)
		}
	}
	c := Config{AgentIP: "2001:0db8::1"}
	if err := normalizeMonitoring(&c, "/base", targetPathRules(false)); err != nil || c.AgentIP != "2001:db8::1" {
		t.Fatalf("IP was not normalized: %+v %v", c, err)
	}
}
