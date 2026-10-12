package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoteBootstrapWithoutLocalConfig(t *testing.T) {
	base := t.TempDir()
	c, err := BootstrapConfig(Config{}, base, "192.0.2.1, [2001:db8::1]:12345", "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	if !c.WaitingForConfig() || c.Login.Enabled || c.MD5.Enabled || c.Existence.Enabled || c.History != nil {
		t.Fatal("remote bootstrap enabled collection without an assignment")
	}
	if c.Server[0] != "192.0.2.1:55555" || c.Server[1] != "[2001:db8::1]:12345" || c.AgentIP != "192.0.2.21" {
		t.Fatalf("incorrect bootstrap transport: %+v", c)
	}
	d := NewConfigDelivery(c, base, "test")
	if d.endpoints[0].tcp != "192.0.2.1:55556" || d.endpoints[1].tcp != "[2001:db8::1]:55556" {
		t.Fatal("bootstrap did not use outbound configuration port")
	}
	for _, master := range []string{"", "not-an-ip", "192.0.2.1:55556", "192.0.2.1:0", "192.0.2.1,", "192.0.2.1,192.0.2.1"} {
		// An explicit UDP 55556 port is valid; config TCP still uses 55556.
		_, err := BootstrapConfig(Config{}, base, master, "")
		if (master == "192.0.2.1:55556") != (err == nil) {
			t.Fatalf("master=%q err=%v", master, err)
		}
	}
	if _, err := BootstrapConfig(Config{}, base, "192.0.2.1", "invalid"); err == nil {
		t.Fatal("invalid machine identity accepted")
	}
}

func TestSavedConnectionSupportsNoArgumentStartup(t *testing.T) {
	base := t.TempDir()
	c, err := BootstrapConfig(Config{}, base, "192.0.2.7", "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(c, base, "test")
	if err := d.persistConnectionSettings(); err != nil {
		t.Fatal(err)
	}
	got, err := BootstrapConfig(Config{}, base, "", "")
	if err != nil || !got.WaitingForConfig() || got.Server[0] != c.Server[0] || got.AgentIP != c.AgentIP {
		t.Fatalf("automatic connection settings could not bootstrap: %+v %v", got, err)
	}
	got, err = BootstrapConfig(Config{}, base, "192.0.2.8", "192.0.2.22")
	if err != nil || got.Server[0] != "192.0.2.8:55555" || got.AgentIP != "192.0.2.22" {
		t.Fatal("explicit settings did not override saved connection")
	}
	for _, invalid := range []string{`{"version":2,"server":["192.0.2.7:55555"]}`, `{"version":1,"server":["not-an-ip"]}`, `{"version":1,"server":[]} {}`, `{"version":1,"unknown":true}`} {
		if err := os.WriteFile(filepath.Join(base, ConnectionFilename), []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := BootstrapConfig(Config{}, base, "", ""); err == nil {
			t.Fatal("invalid saved connection accepted")
		}
		if _, err := BootstrapConfig(Config{}, base, "192.0.2.8", "192.0.2.22"); err != nil {
			t.Fatalf("explicit settings could not recover damaged connection: %v", err)
		}
	}
}

func TestBootstrapOverridesOnlyDeploymentTransport(t *testing.T) {
	c, base := deliveryBootstrap(t)
	got, err := BootstrapConfig(c, base, "192.0.2.7", "192.0.2.8")
	if err != nil || got.WaitingForConfig() || got.OutputDir != filepath.Join(base, "local") || got.AgentIP != "192.0.2.8" || got.Server[0] != "192.0.2.7:55555" {
		t.Fatalf("override changed audit configuration: %+v %v", got, err)
	}
	got, err = BootstrapConfig(c, base, "", "")
	if err != nil || got.Server[0] != c.Server[0] || got.AgentIP != c.AgentIP || got.WaitingForConfig() {
		t.Fatal("omitted deployment settings replaced local transport")
	}
}
