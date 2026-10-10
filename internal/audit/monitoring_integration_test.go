package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func monitoringTestConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	put(t, filepath.Join(dir, "watched", "app.conf"), "first")
	put(t, filepath.Join(dir, "login.jsonl"), "")
	c, err := ParseConfig([]byte(`output_dir: output
state_file: state/agent.json
FilesMonitoring:
  dir: [watched]
login:
  source: jsonl
  path: login.jsonl
setup:
  logs: logs/时间anquan.log
  prom: collector/process_monitor.prom
  interval_seconds: 1
`), dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMonitoringRunOverwritesPromAndPreservesLogsAndState(t *testing.T) {
	c := monitoringTestConfig(t)
	var stdout bytes.Buffer
	first, p1, err := RunWithWriter(c, &stdout)
	if err != nil || !first.Success || !first.Files.BaselineCreated {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	firstProm := read(t, p1.Prom)
	base := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(base, "watched", "app.conf"), "second")
	put(t, filepath.Join(base, "watched", "new.conf"), "new")
	put(t, filepath.Join(base, "login.jsonl"), `{"user":"ops","source_ip":"192.0.2.1","terminal":"N/A","login_time":"2026-10-02T08:00:00+08:00"}`+"\n"+`{"user":"root","source_ip":"192.0.2.2","terminal":"pts/1","login_time":"2026-10-02T08:01:00+08:00"}`+"\n")
	second, p2, err := RunWithWriter(c, &stdout)
	if err != nil || !second.Success || len(second.Files.Changes) != 2 || len(second.Login.Records) != 2 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	secondProm := read(t, p2.Prom)
	if secondProm == firstProm || !strings.Contains(secondProm, `kind="modified"`) || !strings.Contains(secondProm, `user="ops"`) {
		t.Fatal("fixed metrics file was not refreshed with the new findings")
	}
	third, p3, err := RunWithWriter(c, &stdout)
	if err != nil || len(third.Files.Changes) != 0 || len(third.Login.Records) != 0 {
		t.Fatalf("rolling/dedup failed: %+v %v", third, err)
	}
	if p1.Prom != c.Setup.Prom || p1.Prom != p2.Prom || p2.Prom != p3.Prom || p1.Log != p2.Log {
		t.Fatal("scans must reuse the configured metrics file and same daily log")
	}
	entries, err := os.ReadDir(filepath.Dir(p3.Prom))
	if err != nil || len(entries) != 1 || entries[0].Name() != "process_monitor.prom" {
		t.Fatalf("collector must contain only process_monitor.prom: %v, %v", entries, err)
	}
	thirdProm := read(t, p3.Prom)
	if strings.Contains(thirdProm, first.StartedAt.Format(time.RFC3339Nano)) || strings.Contains(thirdProm, second.StartedAt.Format(time.RFC3339Nano)) || strings.Contains(thirdProm, `kind="modified"`) || strings.Contains(thirdProm, `user="ops"`) {
		t.Fatal("fixed metrics file retained stale findings or appended earlier runs")
	}
	if !strings.Contains(thirdProm, third.StartedAt.Format(time.RFC3339Nano)) {
		t.Fatal("fixed metrics file does not describe the latest run")
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	events := map[string]int{}
	for _, line := range lines {
		var v struct {
			Time        time.Time
			Host, Event string
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		_, offset := v.Time.Zone()
		if v.Host == "" || offset != 8*3600 {
			t.Fatalf("missing host/Beijing time: %s", line)
		}
		events[v.Event]++
	}
	if events["scan_started"] != 3 || events["scan_complete"] != 3 || events["ssh_login"] != 2 || events["alert"] != 2 {
		t.Fatalf("events=%v", events)
	}
	if !strings.Contains(read(t, p2.Log), `"before_md5"`) || !strings.Contains(read(t, p2.Log), `"md5"`) {
		t.Fatal("daily logs lack MD5 evidence")
	}
	series := map[string]bool{}
	for _, p := range []string{p3.Prom, p3.Latest} {
		for _, line := range strings.Split(read(t, p), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			i := strings.LastIndexByte(line, ' ')
			key := line[:i]
			if series[key] {
				t.Fatalf("duplicate metric: %s", line)
			}
			if p == p3.Prom && (!strings.HasPrefix(line, "anqu_snapshot_") || !strings.Contains(key, "run_id=") || !strings.Contains(key, "host=")) {
				t.Fatalf("monitoring metric schema changed: %s", line)
			}
			series[key] = true
		}
	}
	if strings.Contains(read(t, p2.Latest), "anqu_snapshot_") {
		t.Fatal("latest metrics must remain stable series")
	}
}

func TestMonitoringPublishFailureDoesNotConsumeChangeOrLogin(t *testing.T) {
	c := monitoringTestConfig(t)
	runOK(t, c)
	base := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(base, "watched", "app.conf"), "modified")
	put(t, filepath.Join(base, "login.jsonl"), `{"user":"ops","terminal":"N/A","login_time":"2026-10-02T08:00:00+08:00"}`+"\n")
	beforeFiles, beforeLogin := read(t, c.StateFile+".files"), read(t, c.StateFile+".logins")
	blocked := filepath.Join(base, "blocked")
	put(t, blocked, "not a directory")
	c.Setup.Prom = filepath.Join(blocked, "process_monitor.prom")
	if _, _, err := Run(c); err == nil {
		t.Fatal("expected publish failure")
	}
	if read(t, c.StateFile+".files") != beforeFiles || read(t, c.StateFile+".logins") != beforeLogin {
		t.Fatal("failed output consumed baseline/cursor")
	}
	c.Setup.Prom = filepath.Join(base, "collector", "process_monitor.prom")
	r, _ := runOK(t, c)
	if len(r.Files.Changes) != 1 || len(r.Login.Records) != 1 {
		t.Fatalf("findings lost: %+v", r)
	}
}

func TestBeijingDailyRotationAndTimestampTemplates(t *testing.T) {
	dir := t.TempDir()
	c := Config{OutputDir: dir}
	before := time.Date(2026, 10, 2, 15, 59, 59, 0, time.UTC)
	after := before.Add(time.Second)
	if err := writeLog(c, nil, before, "test", nil); err != nil {
		t.Fatal(err)
	}
	if err := writeLog(c, nil, after, "test", nil); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(logPath(c, before)) != "20261002anquan.log" || filepath.Base(logPath(c, after)) != "20261003anquan.log" {
		t.Fatal("rotation did not occur at Beijing midnight")
	}
	for _, name := range []string{"anquan.log", "{date}anquan.log", "时间anquan.log"} {
		if dailyLogOutput(name, before) == dailyLogOutput(name, after) {
			t.Fatalf("log did not rotate at midnight: %s", name)
		}
		if !logOutputNamePattern(name).MatchString(filepath.Base(dailyLogOutput(name, before))) {
			t.Fatalf("generated name not excluded: %s", name)
		}
	}
	c.Setup = &SetupConfig{Logs: filepath.Join(dir, "external", "时间anquan.log"), Prom: filepath.Join(dir, "external", "process_monitor.prom")}
	c.OutputDir = filepath.Join(dir, "reports")
	if monitoringExcluded(c, filepath.Join(dir, "external", "other-anquan.log")) {
		t.Fatal("unrelated suffix-match file was hidden from monitoring")
	}
	if !monitoringExcluded(c, dailyLogOutput(c.Setup.Logs, before)) {
		t.Fatal("generated log was not excluded")
	}
	if !monitoringExcluded(c, c.Setup.Prom) || monitoringExcluded(c, filepath.Join(dir, "external", "other-process_monitor.prom")) {
		t.Fatal("only the configured metrics file should be excluded")
	}
}

func TestMonitoringPromConfigUsesFixedFilename(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", "/var/lib/node_exporter/textfile_collector/process_monitor.prom"},
		{"collector/", "/base/collector/process_monitor.prom"},
		{"collector", "/base/collector/process_monitor.prom"},
		{"collector/process_monitor.prom", "/base/collector/process_monitor.prom"},
		{"collector/时间process_monitor.prom", "/base/collector/process_monitor.prom"},
		{"collector/{date}process_monitor.prom", "/base/collector/process_monitor.prom"},
		{"collector/{time}process_monitor.prom", "/base/collector/process_monitor.prom"},
		{"collector/custom.prom", "/base/collector/custom.prom"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			c := Config{Setup: &SetupConfig{Prom: tc.input}}
			if err := normalizeMonitoring(&c, "/base", targetPathRules(false)); err != nil {
				t.Fatal(err)
			}
			if c.Setup.Prom != tc.want || c.Setup.Logs != "/var/log/时间anquan.log" {
				t.Fatalf("unexpected output config: %+v", c.Setup)
			}
		})
	}
}

func TestMonitoringLegacyPromTemplateOverwritesFixedFile(t *testing.T) {
	for _, tc := range []struct{ name, token string }{
		{"chinese", "时间"}, {"date", "{date}"}, {"time", "{time}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := monitoringTestConfig(t)
			c.Setup.Prom = filepath.Join(filepath.Dir(c.Setup.Prom), tc.token+"process_monitor.prom")
			if err := normalizeMonitoring(&c, filepath.Dir(c.OutputDir), nativePathRules()); err != nil {
				t.Fatal(err)
			}
			_, first := runOK(t, c)
			_, second := runOK(t, c)
			entries, err := os.ReadDir(filepath.Dir(second.Prom))
			if err != nil || first.Prom != second.Prom || len(entries) != 1 || entries[0].Name() != "process_monitor.prom" {
				t.Fatalf("legacy template did not reuse fixed file: %v, %v", entries, err)
			}
		})
	}
}

func TestUDPNotificationEnvelopeAndNoMasterMode(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	r := Report{Host: "test-host", StartedAt: time.Now(), Success: true, Alerts: []Alert{{Module: "files", Kind: "deleted", Target: "/tmp/example", Message: "removed"}}}
	r.Login.Records = []LoginRecord{{User: "ops", LoginTime: r.StartedAt, SourceIP: "192.0.2.1", Terminal: "N/A"}}
	results := notifyServers(Config{Server: []string{listener.LocalAddr().String()}}, r)
	if len(results) != 1 || results[0].Error != "" || results[0].Sent != 3 || results[0].IP != "127.0.0.1" {
		t.Fatalf("results=%+v", results)
	}
	kinds := map[string]bool{}
	ids := map[string]bool{}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 3; i++ {
		b := make([]byte, 65536)
		n, _, err := listener.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Version    int
			EventID    string `json:"event_id"`
			Host, Type string
			IP         string `json:"ip"`
		}
		if err := json.Unmarshal(b[:n], &e); err != nil {
			t.Fatal(err)
		}
		if e.Version != 1 || e.EventID == "" || ids[e.EventID] || e.Host != "test-host" || e.IP != "127.0.0.1" {
			t.Fatalf("bad envelope %s", b[:n])
		}
		kinds[e.Type] = true
		ids[e.EventID] = true
	}
	if !kinds["scan_summary"] || !kinds["alert"] || !kinds["ssh_login"] {
		t.Fatal(kinds)
	}
	if len(notifyServers(Config{}, r)) != 0 {
		t.Fatal("empty server must work without a master")
	}
}

func TestServiceContinuesAfterFailureAndStopsCleanly(t *testing.T) {
	c := monitoringTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	calls := 0
	err := serve(ctx, c, &out, "test", func(Config, io.Writer) (Report, OutputPaths, error) {
		calls++
		if calls == 1 {
			return Report{}, OutputPaths{}, os.ErrPermission
		}
		cancel()
		return Report{Success: true}, OutputPaths{}, nil
	})
	if err != nil || calls != 2 || !strings.Contains(out.String(), `"event":"service_started"`) || !strings.Contains(out.String(), `"event":"service_stopped"`) {
		t.Fatalf("calls=%d err=%v out=%s", calls, err, out.String())
	}
}

func TestNewConfigDefaultsAndValidation(t *testing.T) {
	valid := `FilesMonitoring:
  fils:
    - /etc/ssh/sshd_config|/etc/ssh/ssh_config,900150983cd24fb0d6963f7d28e17f72,d41d8cd98f00b204e9800998ecf8427e
    - /etc/hosts.allow
  dir: [/etc/cron.d/]
  search:
    - authorized_keys,/root|/home/|/var/,900150983cd24fb0d6963f7d28e17f72
    - id_rsa,/root|/home/|/var/
ProcessMonitoring:
  exists:
    - '/usr/sbin/sshd -D|/usr/sbin/ssh -D'
  Process:
    whitelist: ['/usr/sbin/sshd -D']
server: ['172.22.0.100:55555']
setup:
  logs: /var/log/时间anquan.log
  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom
`
	if err := ValidateEmbeddedYAML([]byte(valid), "linux"); err != nil {
		t.Fatal(err)
	}
	c, err := decodeYAML([]byte(valid))
	if err != nil || c.MD5.Enabled || c.Existence.Enabled || c.Login.Source != "journal" {
		t.Fatalf("new defaults %+v %v", c, err)
	}
	for _, data := range []string{strings.Replace(valid, "900150983cd24fb0d6963f7d28e17f72", "md51", 1), valid + "  interval_seconds: -1\n", strings.Replace(valid, "172.22.0.100:55555", "172.22.0.100:99999", 1), strings.Replace(valid, "时间anquan.log", "{time}anquan.log", 1), valid + "  typo: true\n"} {
		if err := ValidateEmbeddedYAML([]byte(data), "linux"); err == nil {
			t.Fatalf("invalid config accepted: %s", data)
		}
	}
}
