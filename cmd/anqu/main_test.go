package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/audit"
	"anqu/internal/defaults"
	"anqu/internal/install"
	"anqu/internal/sealed"
)

// Runtime tests inject deployment so they never install into the test host.
func run(args []string, stdout, stderr io.Writer, load func() ([]byte, error), executable func() (string, error)) int {
	return runPrepared(args, stdout, stderr, load, executable, func(path string, _ []string, _ io.Writer) (install.Preparation, error) {
		return install.Preparation{Path: path}, nil
	})
}

func logEvents(t *testing.T, directory, event string) []json.RawMessage {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.log"))
	if err != nil {
		t.Fatal(err)
	}
	var events []json.RawMessage
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var entry struct {
				Event string
				Data  json.RawMessage
			}
			if err := decoder.Decode(&entry); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if entry.Event == event {
				events = append(events, entry.Data)
			}
		}
	}
	return events
}

func assertNoReports(t *testing.T, directory string) {
	t.Helper()
	reports, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil || len(reports) != 0 {
		t.Fatalf("timestamped JSON reports remain: %v %v", reports, err)
	}
}

func TestPreparationPrecedesConfigurationAndHelpHasNoSideEffects(t *testing.T) {
	for _, args := range [][]string{{"-help"}, {"-version"}, {"-invalid"}, nil} {
		var stdout, stderr bytes.Buffer
		prepared := false
		code := runPrepared(args, &stdout, &stderr, func() ([]byte, error) {
			t.Fatal("configuration loaded after failed installation")
			return nil, nil
		}, func() (string, error) { return "uploaded-agent", nil }, func(path string, received []string, _ io.Writer) (install.Preparation, error) {
			prepared = true
			if path != "uploaded-agent" || len(received) != 0 {
				t.Fatal("wrong deployment inputs")
			}
			return install.Preparation{}, errors.New("first deployment requires root")
		})
		if len(args) == 0 {
			if code != 1 || !prepared || !strings.Contains(stderr.String(), "requires root") {
				t.Fatalf("installation failure: %d %t %q", code, prepared, stderr.String())
			}
		} else if prepared {
			t.Fatal("help/version/invalid argument performed installation")
		}
	}
}

func TestFreshNodeServiceInstallationReturnsWithoutDuplicateForegroundAudit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPrepared(nil, &stdout, &stderr, func() ([]byte, error) {
		t.Fatal("installation-only launch tried to start auditing")
		return nil, os.ErrNotExist
	}, func() (string, error) { return "uploaded-agent", nil }, func(string, []string, io.Writer) (install.Preparation, error) {
		return install.Preparation{Path: install.Executable, InstallOnly: true}, nil
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("fresh install failed: %d %q", code, stderr.String())
	}
}

func TestAgentRejectsExternalConfigWithoutLoadingPayload(t *testing.T) {
	for _, args := range [][]string{{"-config", "secret.yaml"}, {"-check-config"}, {"secret.yaml"}, {"-dump-config"}, {"-once"}} {
		var stdout, stderr bytes.Buffer
		loaded := false
		code := run(args, &stdout, &stderr, func() ([]byte, error) { loaded = true; return nil, nil }, os.Executable)
		if code != 1 || loaded || strings.Contains(stderr.String(), "secret.yaml") {
			t.Fatalf("args=%v code=%d loaded=%t stderr=%s", args, code, loaded, stderr.String())
		}
	}
}

func TestAgentHelpAndVersionDoNotLoadConfig(t *testing.T) {
	for _, arg := range []string{"-help", "-version"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{arg}, &stdout, &stderr, func() ([]byte, error) { t.Fatal("must not decrypt config"); return nil, nil }, os.Executable)
		if code != 0 {
			t.Fatalf("%s failed", arg)
		}
		if arg == "-version" && stdout.String() != "anqu "+version+"\n" {
			t.Fatal("unexpected version output")
		}
		if arg == "-help" && (!strings.Contains(stderr.String(), defaults.MasterAddress) || !strings.Contains(stderr.String(), "agent.service")) {
			t.Fatal("help omits the fixed-domain service installation")
		}
	}
}

func TestAgentErrorsDoNotPrintConfiguration(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		data := []byte("private_secret_field: 'PRIVATE_CONFIG_MARKER'\n")
		code := run(nil, &stdout, &stderr, func() ([]byte, error) {
			if invalid {
				return data, nil
			}
			return nil, errors.New("decryption failed PRIVATE_CONFIG_MARKER")
		}, func() (string, error) { return filepath.Join(t.TempDir(), "anqu"), nil })
		if code != 1 || stderr.Len() != 0 || stdout.Len() != 0 {
			t.Fatalf("sensitive runtime error: %s %s", stdout.String(), stderr.String())
		}
		if invalid && !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("decrypted source not cleared after parse failure")
		}
	}
}

func TestAgentUsesExecutableDirectoryWithoutConfigFile(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	data := []byte("output_dir: output\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\n")
	code := run(nil, &stdout, &stderr, func() ([]byte, error) { return data, nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "output", "textfile", "anqu.prom")); err != nil {
		t.Fatal(err)
	}
	logs, err := filepath.Glob(filepath.Join(dir, "output", "logs", "*.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs=%v err=%v", logs, err)
	}
	logData, err := os.ReadFile(logs[0])
	if err != nil || !bytes.Contains(logData, []byte(`"event":"agent_started"`)) || !bytes.Contains(logData, []byte(`"event":"scan_complete"`)) {
		t.Fatalf("local lifecycle logs missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("agent wrote or required a YAML configuration file")
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("decrypted YAML source not cleared")
	}
}

func TestAgentFindingsExitTwoAndPreserveRealPathsInLogs(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	data := []byte("output_dir: output\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  base_dir: watched\n  files:\n    - path: missing.conf\n")
	code := run(nil, &stdout, &stderr, func() ([]byte, error) { return data, nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
	if code != 2 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	assertNoReports(t, filepath.Join(dir, "output"))
	alerts := logEvents(t, filepath.Join(dir, "output", "logs"), "alert")
	if len(alerts) == 0 || !bytes.Contains(alerts[0], []byte("missing.conf")) {
		t.Fatalf("real path absent from findings: %s", alerts)
	}
}

func TestAgentEachInvocationUsesCurrentConfigAndFreshBaseline(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"first.conf", "second.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for step, name := range []string{"first.conf", "second.conf", "second.conf"} {
		var stdout, stderr bytes.Buffer
		config := "output_dir: output\nFilesMonitoring:\n  fils: [" + name + "]\nlogin:\n  enabled: false\nsetup:\n  logs: logs/agent.log\n  prom: collector/agent.prom\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat(name, step+1)), 0600); err != nil {
			t.Fatal(err)
		}
		code := run(nil, &stdout, &stderr, func() ([]byte, error) { return []byte(config), nil }, func() (string, error) { return filepath.Join(dir, "anqu"), nil })
		if code != 0 {
			t.Fatalf("fresh invocation rejected config/current content: code=%d stderr=%s", code, stderr.String())
		}
	}
	assertNoReports(t, filepath.Join(dir, "output"))
	results := logEvents(t, filepath.Join(dir, "logs"), "files_result")
	if len(results) != 3 {
		t.Fatalf("missing file results: %d", len(results))
	}
	for _, data := range results {
		var files audit.FilesResult
		if err := json.Unmarshal(data, &files); err != nil || !files.BaselineCreated || len(files.Changes) != 0 {
			t.Fatalf("invocation reused previous lifetime baseline: %+v %v", files, err)
		}
	}
}

func TestAgentInvalidMasterDoesNotScan(t *testing.T) {
	t.Setenv("ANQUAN_MASTER", "http://sa.sa.ops.tw/")
	t.Setenv("ANQUAN_AGENT_IP", "")
	base := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"-service"}, &stdout, &stderr, func() ([]byte, error) { return nil, os.ErrNotExist }, func() (string, error) { return filepath.Join(base, "anqu"), nil })
	if code != 1 || !strings.Contains(stderr.String(), "invalid bootstrap settings") {
		t.Fatalf("invalid Master was not rejected: %d %q", code, stderr.String())
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatal("missing configuration created collection output")
	}
}

func TestAgentCachedMasterConfigStartsWithoutLocalConfig(t *testing.T) {
	for _, useEnv := range []bool{false, true} {
		t.Run(map[bool]string{false: "flags", true: "environment"}[useEnv], func(t *testing.T) {
			t.Setenv("ANQUAN_MASTER", "")
			t.Setenv("ANQUAN_AGENT_IP", "")
			base := t.TempDir()
			ciphertext, err := sealed.EncryptConfig([]byte("output_dir: assigned\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin: {enabled: false}\nserver: []\nsetup: {logs: assigned/logs/agent.log, prom: assigned/agent.prom, interval_seconds: 1}\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, sealed.MasterConfigFilename), ciphertext, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-master", "127.0.0.1"}
			if useEnv {
				t.Setenv("ANQUAN_MASTER", "127.0.0.1")
				t.Setenv("ANQUAN_AGENT_IP", "192.0.2.21")
				args = nil
			}
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr, func() ([]byte, error) { return nil, os.ErrNotExist }, func() (string, error) { return filepath.Join(base, "anqu"), nil })
			if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("cached master config could not run without config.age: %d %s %s", code, stdout.String(), stderr.String())
			}
			assertNoReports(t, filepath.Join(base, "assigned"))
			if results := logEvents(t, filepath.Join(base, "assigned", "logs"), "scan_complete"); len(results) != 1 {
				t.Fatal("cached master configuration was not collected")
			}
			if _, err := os.Stat(filepath.Join(base, sealed.ConfigFilename)); !os.IsNotExist(err) {
				t.Fatal("remote-only invocation created a local configuration")
			}
		})
	}
}

func TestNoArgumentHostnameCheckFetchesMasterConfigAndReportsSSHLogin(t *testing.T) {
	base := t.TempDir()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_, port, err := net.SplitHostPort(tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANQUAN_MASTER", net.JoinHostPort("localhost", port))
	t.Setenv("ANQUAN_AGENT_IP", "10.0.0.28")
	loginPath := filepath.Join(base, "login.jsonl")
	putLogin := func(id string) {
		t.Helper()
		data, _ := json.Marshal(map[string]any{"id": id, "user": "ops", "source_ip": "192.0.2.50", "terminal": "N/A", "login_time": time.Now().Format(time.RFC3339Nano)})
		if err := os.WriteFile(loginPath, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	putLogin("first-login")
	ciphertext, err := sealed.EncryptConfig([]byte("output_dir: assigned\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin: {enabled: true, source: jsonl, path: login.jsonl}\nserver: [" + udp.LocalAddr().String() + "]\nsetup: {logs: assigned/logs/agent.log, prom: assigned/agent.prom, interval_seconds: 1}\n"))
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		decoder := json.NewDecoder(conn)
		var hello map[string]any
		if err := decoder.Decode(&hello); err != nil {
			served <- err
			return
		}
		if hello["type"] != "hello" || hello["discover_ip"] != true || hello["ip"] != nil {
			served <- fmt.Errorf("incorrect hello: %+v", hello)
			return
		}
		if err := json.NewEncoder(conn).Encode(map[string]any{"version": 1, "type": "identity", "ip": "192.0.2.21"}); err != nil {
			served <- err
			return
		}
		if err := json.NewEncoder(conn).Encode(map[string]any{"version": 1, "type": "config", "revision": fmt.Sprintf("%x", sha256.Sum256(ciphertext)), "ciphertext": string(ciphertext)}); err != nil {
			served <- err
			return
		}
		var ack map[string]any
		err = decoder.Decode(&ack)
		if err == nil && (ack["type"] != "ack" || ack["error"] != nil) {
			err = fmt.Errorf("assignment rejected: %+v", ack)
		}
		served <- err
	}()
	runCheck := func(wantLogin, wantIP string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := run(nil, &stdout, &stderr, func() ([]byte, error) { return nil, os.ErrNotExist }, func() (string, error) { return filepath.Join(base, "anqu"), nil })
		if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("no-argument check failed: %d %q %q", code, stdout.String(), stderr.String())
		}
		_ = udp.SetReadDeadline(time.Now().Add(time.Second))
		for {
			packet := make([]byte, 65536)
			n, _, err := udp.ReadFrom(packet)
			if err != nil {
				t.Fatalf("no-argument check did not report SSH login: %v", err)
			}
			var event struct {
				Type string `json:"type"`
				IP   string `json:"ip"`
				Data struct {
					ID       string `json:"id"`
					SourceIP string `json:"source_ip"`
				} `json:"data"`
			}
			if err := json.Unmarshal(packet[:n], &event); err != nil {
				t.Fatal(err)
			}
			if event.Type == "ssh_login" {
				if event.IP != wantIP || event.Data.ID != wantLogin || event.Data.SourceIP != "192.0.2.50" {
					t.Fatalf("wrong SSH login identity: %+v", event)
				}
				break
			}
		}
	}
	runCheck("first-login", "192.0.2.21")
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	// A later interactive invocation needs neither flags nor environment nor a
	// local config: it uses the saved connection plus encrypted master cache.
	t.Setenv("ANQUAN_MASTER", "")
	t.Setenv("ANQUAN_AGENT_IP", "")
	putLogin("second-login")
	// A legacy observed peer may be a relay, so it is not restored as a local
	// machine identity when this loopback-only test cannot select a real route.
	runCheck("second-login", "")
	assertNoReports(t, filepath.Join(base, "assigned"))
	if results := logEvents(t, filepath.Join(base, "assigned", "logs"), "scan_complete"); len(results) != 2 {
		t.Fatal("no-argument invocation did not perform exactly one scan")
	}
}
