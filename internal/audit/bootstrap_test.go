package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoteBootstrapWithoutLocalConfig(t *testing.T) {
	base := t.TempDir()
	c, err := BootstrapConfig(Config{}, base, "192.0.2.1, [2001:db8::1]:12345")
	if err != nil {
		t.Fatal(err)
	}
	if !c.WaitingForConfig() || c.Login.Enabled || c.MD5.Enabled || c.Existence.Enabled || len(c.Server) != 0 || c.reportedIP() != "" {
		t.Fatal("bootstrap selected collection, identity or UDP destination")
	}
	d := NewConfigDelivery(c, base, "test")
	if d.endpoints[0].tcp != "192.0.2.1:55556" || d.endpoints[1].tcp != "[2001:db8::1]:12345" {
		t.Fatal("incorrect TCP destinations")
	}
	for _, master := range []string{"", "not-an-ip", "192.0.2.1:0", "192.0.2.1,", "192.0.2.1,192.0.2.1"} {
		if _, err := BootstrapConfig(Config{}, base, master); err == nil {
			t.Fatalf("invalid master=%q accepted", master)
		}
	}
}

func TestSavedConnectionSupportsNoArgumentStartup(t *testing.T) {
	base := t.TempDir()
	c, err := BootstrapConfig(Config{}, base, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(c, base, "test")
	if err := d.observeIP("49.7.214.217"); err != nil {
		t.Fatal(err)
	}
	got, err := BootstrapConfig(Config{}, base, "")
	if err != nil || !got.WaitingForConfig() || got.masters[0] != c.masters[0] || got.reportedIP() != "49.7.214.217" {
		t.Fatalf("saved connection/observed IP lost: %+v %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(base, ConnectionFilename), []byte(`{"version":1,"server":["192.0.2.7:55555"],"agent_ip":"10.0.0.28"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = BootstrapConfig(Config{}, base, "")
	if err != nil || got.masters[0] != "192.0.2.7:55556" || got.reportedIP() != "" {
		t.Fatal("v1 preserved manual identity or UDP control port")
	}
	for _, invalid := range []string{`{"version":3}`, `{"version":2,"master":["not-an-ip"]}`, `{"version":2,"master":[]} {}`, `{"version":2,"unknown":true}`} {
		if err := os.WriteFile(filepath.Join(base, ConnectionFilename), []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := BootstrapConfig(Config{}, base, ""); err == nil {
			t.Fatal("invalid saved connection accepted")
		}
		if _, err := BootstrapConfig(Config{}, base, "192.0.2.8"); err != nil {
			t.Fatalf("explicit master could not recover damaged connection: %v", err)
		}
	}
}

func TestBootstrapSeparatesTCPFromYAMLReportDestinations(t *testing.T) {
	base := t.TempDir()
	c, err := ParseConfig([]byte("output_dir: local\nserver: [192.168.0.1,192.168.0.2]\nlogin: {enabled: false}\nagent_ip: 10.0.0.28\nsetup: {logs: logs/agent.log, prom: metrics/agent.prom}\n"), base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BootstrapConfig(c, base, "8.217.222.30")
	if err != nil || got.WaitingForConfig() || got.OutputDir != filepath.Join(base, "local") || got.reportedIP() != "" || got.Server[0] != "192.168.0.1:55555" || got.Server[1] != "192.168.0.2:55555" || got.masters[0] != "8.217.222.30:55556" {
		t.Fatalf("TCP bootstrap changed UDP servers or accepted manual IP: %+v %v", got, err)
	}
	got, err = BootstrapConfig(c, base, "")
	if err != nil || len(NewConfigDelivery(got, base, "test").endpoints) != 0 {
		t.Fatal("UDP list unexpectedly opened TCP connections")
	}
}
