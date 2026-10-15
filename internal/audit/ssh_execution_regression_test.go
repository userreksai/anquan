package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sshExecutionTestConnection = "192.0.2.4 48222 10.20.30.40 22"

func sshExecutionRegressionConfig(t *testing.T, endpoint string) (Config, LoginRecord) {
	t.Helper()
	base := t.TempDir()
	yaml := fmt.Sprintf("output_dir: output\nstate_file: state/agent.json\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin:\n  enabled: true\n  source: jsonl\n  path: login.jsonl\n  poll_interval_ms: 100\nserver: ['%s']\nsetup:\n  logs: logs/agent.log\n  prom: collector/process_monitor.prom\n  interval_seconds: 300\n", endpoint)
	c, err := ParseConfig([]byte(yaml), base)
	if err != nil {
		t.Fatal(err)
	}
	record := LoginRecord{ID: "original-login", User: "ops", Method: "publickey", SourceIP: "192.0.2.4", SourcePort: 48222, Terminal: "pts/2", LoginTime: time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	put(t, c.Login.Path, string(data)+"\n")
	return c, record
}

func sshExecutionRegressionRequest(t *testing.T) SSHExecutionRequest {
	t.Helper()
	req, err := NewSSHExecutionRequest(sshExecutionTestConnection)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestSSHExecutionReportsConsumedLoginOnEveryExplicitRequest(t *testing.T) {
	listener := heartbeatListener(t)
	c, original := sshExecutionRegressionConfig(t, listener.LocalAddr().String())
	collected, state, issues := collectSSHLogins(c, time.Now())
	if len(issues) != 0 || len(collected.Records) != 1 {
		t.Fatalf("could not establish an already-consumed login: %+v %v", collected, issues)
	}
	saveLoginState(t, c, state)
	cursorBefore := read(t, c.StateFile+".logins")
	latestProm := filepath.Join(c.OutputDir, "textfile", "anqu.prom")
	put(t, c.Setup.Prom, "existing configured metrics\n")
	put(t, latestProm, "existing latest metrics\n")
	sourceBefore := read(t, c.Login.Path)
	caller := SSHExecutionCaller{UID: 1001, PID: 1234, Username: "ops"}
	var output bytes.Buffer
	requests := []SSHExecutionRequest{sshExecutionRegressionRequest(t), sshExecutionRegressionRequest(t)}
	if requests[0].ID == requests[1].ID {
		t.Fatal("separate execution requests reused an ID")
	}
	for _, req := range requests {
		record, err := ReportSSHExecution(context.Background(), c, &output, req, caller)
		if err != nil {
			t.Fatal(err)
		}
		if record.ID != req.ID || record.ID == original.ID || record.SourceRecordID != original.ID || record.Trigger != "execution" || !record.LoginTime.Equal(original.LoginTime) || record.User != original.User || record.SourceIP != original.SourceIP || record.SourcePort != original.SourcePort || record.InvokedAt == nil || record.ExecutedBy != caller.Username {
			t.Fatalf("explicit execution lost its identity or original SSH evidence: %+v", record)
		}
		if !record.InvokedAt.After(original.LoginTime) {
			t.Fatalf("execution time did not remain distinct from the login time: %+v", record)
		}
	}
	packets := sshRealtimePackets(t, listener, 100*time.Millisecond)
	if len(packets) != 2 {
		t.Fatalf("each explicit execution must send exactly one event: %+v", packets)
	}
	for i, packet := range packets {
		var record LoginRecord
		if err := json.Unmarshal(packet.Data, &record); err != nil {
			t.Fatal(err)
		}
		if packet.Type != "ssh_login" || record.ID != requests[i].ID || record.Trigger != "execution" || record.SourceRecordID != original.ID || !record.LoginTime.Equal(original.LoginTime) {
			t.Fatalf("incorrect execution event: %+v %+v", packet, record)
		}
	}
	if packets[0].EventID == packets[1].EventID {
		t.Fatal("Master would deduplicate two separate execution requests")
	}
	if read(t, c.StateFile+".logins") != cursorBefore || read(t, c.Login.Path) != sourceBefore {
		t.Fatal("execution reporting changed the incremental login cursor or source")
	}
	if read(t, c.Setup.Prom) != "existing configured metrics\n" || read(t, latestProm) != "existing latest metrics\n" {
		t.Fatal("execution reporting replaced full-scan metrics")
	}
}

func TestSSHExecutionRejectsIneligibleRequestsWithoutSending(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config, *SSHExecutionRequest, *SSHExecutionCaller)
	}{
		{"disabled", func(c *Config, _ *SSHExecutionRequest, _ *SSHExecutionCaller) { c.Login.Enabled = false }},
		{"waiting-for-configuration", func(c *Config, _ *SSHExecutionRequest, _ *SSHExecutionCaller) { c.waitingForConfig = true }},
		{"no-reporting-server", func(c *Config, _ *SSHExecutionRequest, _ *SSHExecutionCaller) { c.Server = nil }},
		{"poll-mode", func(c *Config, _ *SSHExecutionRequest, _ *SSHExecutionCaller) { c.Login.Mode = "poll" }},
		{"source-address-mismatch", func(_ *Config, req *SSHExecutionRequest, _ *SSHExecutionCaller) {
			req.Connection = "192.0.2.99 48222 10.20.30.40 22"
		}},
		{"source-port-mismatch", func(_ *Config, req *SSHExecutionRequest, _ *SSHExecutionCaller) {
			req.Connection = "192.0.2.4 48223 10.20.30.40 22"
		}},
		{"caller-user-mismatch", func(_ *Config, _ *SSHExecutionRequest, caller *SSHExecutionCaller) {
			caller.Username = "another-user"
		}},
		{"unprivileged-request-without-connection", func(_ *Config, req *SSHExecutionRequest, _ *SSHExecutionCaller) {
			req.Connection = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := heartbeatListener(t)
			c, _ := sshExecutionRegressionConfig(t, listener.LocalAddr().String())
			req := sshExecutionRegressionRequest(t)
			caller := SSHExecutionCaller{UID: 1001, PID: 1234, Username: "ops"}
			tc.mutate(&c, &req, &caller)
			if _, err := ReportSSHExecution(context.Background(), c, nil, req, caller); err == nil {
				t.Fatal("ineligible execution was accepted")
			}
			if packets := sshRealtimePackets(t, listener, 50*time.Millisecond); len(packets) != 0 {
				t.Fatalf("ineligible execution sent UDP events: %+v", packets)
			}
			if _, err := os.Stat(c.StateFile + ".logins"); !os.IsNotExist(err) {
				t.Fatalf("rejected execution touched incremental login state: %v", err)
			}
		})
	}
}

func TestSSHExecutionDefaultTriggerServiceDoesNotAddThirdLogin(t *testing.T) {
	listener := heartbeatListener(t)
	c, _ := sshExecutionRegressionConfig(t, listener.LocalAddr().String())
	if c.Login.Mode != "trigger" {
		t.Fatalf("default login mode=%q, want trigger", c.Login.Mode)
	}
	caller := SSHExecutionCaller{UID: 1001, PID: 1234, Username: "ops"}
	for i := 0; i < 2; i++ {
		if _, err := ReportSSHExecution(context.Background(), c, nil, sshExecutionRegressionRequest(t), caller); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	scanned := make(chan Report, 1)
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(1500 * time.Millisecond):
				t.Error("trigger-mode service did not stop")
			}
		}
	})
	go func() {
		done <- serve(ctx, c, nil, "ssh-trigger-regression", func(active Config, writer io.Writer) (Report, OutputPaths, error) {
			report, paths, err := runWithWriter(active, writer, false)
			scanned <- report
			cancel()
			return report, paths, err
		})
	}()
	select {
	case report := <-scanned:
		if !report.Success || len(report.Login.Records) != 0 {
			t.Fatalf("trigger-mode service scan automatically collected SSH logins: %+v", report)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("trigger-mode service did not complete its first full scan")
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("trigger-mode service did not stop after its scan")
	}
	packets := sshRealtimePackets(t, listener, 100*time.Millisecond)
	records := sshRealtimeRecords(t, packets)
	if len(records) != 2 || records[0].Trigger != "execution" || records[1].Trigger != "execution" {
		t.Fatalf("automatic service work added a third SSH event: %+v", records)
	}
	if _, err := os.Stat(c.StateFile + ".logins"); !os.IsNotExist(err) {
		t.Fatalf("trigger-mode service unexpectedly advanced the polling cursor: %v", err)
	}
}
