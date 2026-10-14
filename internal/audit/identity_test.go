package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"anqu/internal/sealed"
)

func TestObservedFallbackAppliesToAllUDPServersButIsNotRestoredAsLocalIdentity(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "identity-test")
	if err := d.observeIP("49.7.214.217"); err != nil {
		t.Fatal(err)
	}
	first, second := heartbeatListener(t), heartbeatListener(t)
	yaml := fmt.Sprintf("output_dir: assigned\nserver: [%s,%s]\nagent_ip: 10.0.0.28\nlogin: {enabled: false}\nsetup: {logs: logs/agent.log, prom: metrics/agent.prom}\n", first.LocalAddr(), second.LocalAddr())
	ciphertext, err := sealed.EncryptConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	frame := configFrame{Version: 1, Type: "config", Revision: configRevision(ciphertext), Ciphertext: string(ciphertext)}
	if err := d.accept(frame, commitAssignment); err != nil {
		t.Fatal(err)
	}
	if d.endpoints[0].tcp != cfg.masters[0] || d.current.Server[0] != first.LocalAddr().String() || d.current.Server[1] != second.LocalAddr().String() || d.current.reportedIP() != "49.7.214.217" {
		t.Fatal("assignment changed TCP destination/identity or failed to change UDP targets")
	}
	activeCopy := d.current
	for _, ip := range []string{"49.7.214.217", "203.0.113.50"} {
		if err := d.observeIP(ip); err != nil {
			t.Fatal(err)
		}
		if results := NotifyHeartbeat(activeCopy, "test"); len(results) != 2 || results[0].Error != "" || results[1].Error != "" {
			t.Fatalf("failed to notify all masters: %+v", results)
		}
		if readHeartbeatPacket(t, first).IP != ip || readHeartbeatPacket(t, second).IP != ip {
			t.Fatal("multiple masters received different or stale machine identities")
		}
	}
	for _, invalid := range []string{"0.0.0.0", "::", "224.0.0.1", "invalid", "49.7.214.217:55556"} {
		if d.observeIP(invalid) == nil || activeCopy.reportedIP() != "203.0.113.50" {
			t.Fatal("invalid discovery changed active identity")
		}
	}
	stored, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := sealed.DecryptConfig(stored)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	var metadata map[string]any
	if err := json.Unmarshal(plaintext, &metadata); err != nil || metadata["observed_ip"] != "203.0.113.50" || metadata["agent_ip"] != nil {
		t.Fatal("discovered IP was not saved as runtime metadata")
	}
	restored, err := BootstrapConfig(Config{}, base, "")
	if err != nil {
		t.Fatal(err)
	}
	cached, err := NewConfigDelivery(restored, base, "test").CachedConfig()
	if err != nil || cached.reportedIP() != "" || cached.Server[1] != second.LocalAddr().String() {
		t.Fatal("restart restored a relay identity or lost assigned report destinations")
	}
}

func TestBareUDPAddressesNormalizeAndDeduplicate(t *testing.T) {
	data := []byte("output_dir: local\nserver: [192.168.0.1,192.168.0.2,'2001:db8::1']\nlogin: {enabled: false}\nsetup: {logs: logs/agent.log, prom: metrics/agent.prom}\n")
	c, err := ParseConfig(data, t.TempDir())
	if err != nil || c.Server[0] != "192.168.0.1:55555" || c.Server[1] != "192.168.0.2:55555" || c.Server[2] != "[2001:db8::1]:55555" {
		t.Fatalf("bare IP list not supported: %+v %v", c, err)
	}
	if err := ValidateEmbeddedYAML([]byte("server: [192.168.0.1,192.168.0.1:55555]\n"), "linux"); err == nil {
		t.Fatal("equivalent duplicate UDP destinations accepted")
	}
}
