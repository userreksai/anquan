package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anqu/internal/defaults"
	"anqu/internal/sealed"
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
	for _, master := range []string{"https://sa.sa.ops.tw", "invalid/hostname", "192.0.2.1:0", "192.0.2.1,", "192.0.2.1,192.0.2.1", "sa.sa.ops.tw,SA.SA.OPS.TW:55556"} {
		if _, err := BootstrapConfig(Config{}, base, master); err == nil {
			t.Fatalf("invalid master=%q accepted", master)
		}
	}
}

func TestFreshBootstrapUsesDefaultDomainAndPreservesConnectionPriority(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "")
	if err != nil || !cfg.WaitingForConfig() || len(cfg.masters) != 1 || cfg.masters[0] != defaults.MasterAddress+":55556" || len(cfg.Server) != 0 || cfg.reportedIP() != "" {
		t.Fatalf("fresh bootstrap lost its default domain or set UDP/identity: %+v %v", cfg, err)
	}
	cfg, err = BootstrapConfig(Config{}, base, "primary.example.invalid:55557,192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDelivery(cfg, base, "test").observeIP("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	restored, err := BootstrapConfig(Config{}, base, "")
	if err != nil || len(restored.masters) != 2 || restored.masters[0] != "primary.example.invalid:55557" || restored.masters[1] != "192.0.2.7:55556" || restored.reportedIP() != "203.0.113.7" {
		t.Fatalf("default replaced saved domain/IP or observed identity: %+v %v", restored, err)
	}
	overridden, err := BootstrapConfig(Config{}, base, defaults.MasterAddress)
	if err != nil || len(overridden.masters) != 1 || overridden.masters[0] != defaults.MasterAddress+":55556" || overridden.reportedIP() != "203.0.113.7" {
		t.Fatalf("explicit Master did not override saved domain or lost identity: %+v %v", overridden, err)
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
	ciphertext, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil || !bytes.HasPrefix(ciphertext, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatalf("connection is not age encrypted: %v", err)
	}
	for _, plaintext := range []string{"192.0.2.7", "49.7.214.217", "master", "observed_ip"} {
		if bytes.Contains(ciphertext, []byte(plaintext)) {
			t.Fatalf("connection ciphertext exposes %q", plaintext)
		}
	}
	got, err := BootstrapConfig(Config{}, base, "")
	if err != nil || !got.WaitingForConfig() || got.masters[0] != c.masters[0] || got.reportedIP() != "49.7.214.217" {
		t.Fatalf("saved connection/observed IP lost: %+v %v", got, err)
	}
}

func TestLegacyConnectionSettingsMigrateAndRemovePlaintext(t *testing.T) {
	for name, tc := range map[string]struct {
		json string
		ip   string
	}{
		"v1": {`{"version":1,"server":["192.0.2.7:55555"],"agent_ip":"10.0.0.28"}`, ""},
		"v2": {`{"version":2,"master":["192.0.2.7"],"observed_ip":"49.7.214.217"}`, "49.7.214.217"},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			legacy := filepath.Join(base, legacyConnectionFilename)
			if err := os.WriteFile(legacy, []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := BootstrapConfig(Config{}, base, "")
			if err != nil || got.masters[0] != "192.0.2.7:55556" || got.reportedIP() != tc.ip {
				t.Fatalf("migration lost Master/discovered identity: %+v, %v", got, err)
			}
			if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
				t.Fatalf("obsolete plaintext remains: %v", err)
			}
			settings := decryptSavedConnection(t, base)
			if settings.Version != 2 || settings.Master[0] != "192.0.2.7:55556" || settings.ObservedIP != tc.ip || settings.AgentIP != "" || settings.Server != nil {
				t.Fatalf("migration retained legacy fields: %+v", settings)
			}
		})
	}
}

func TestInvalidConnectionSettingsRequireExplicitMasterAndCanBeRepaired(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, invalid := range []string{
			`{"version":3}`, `{"version":2,"master":["invalid/hostname"]}`,
			`{"version":2,"master":[]} {}`, `{"version":2,"unknown":true}`,
			`{"version":2,"master":["192.0.2.7","192.0.2.7:55556"]}`,
			strings.Repeat(" ", maxConnectionBytes+1),
		} {
			base := t.TempDir()
			filename, data := legacyConnectionFilename, []byte(invalid)
			if encrypted {
				filename = ConnectionFilename
				var err error
				data, err = sealed.EncryptConfig(data)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(base, filename), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := BootstrapConfig(Config{}, base, ""); err == nil {
				t.Fatal("invalid saved connection accepted")
			}
			cfg, err := BootstrapConfig(Config{}, base, "192.0.2.8")
			if err != nil {
				t.Fatalf("explicit master could not recover damaged connection: %v", err)
			}
			if err := NewConfigDelivery(cfg, base, "test").persistConnectionSettings(); err != nil {
				t.Fatal(err)
			}
			got, err := BootstrapConfig(Config{}, base, "")
			if err != nil || got.masters[0] != "192.0.2.8:55556" {
				t.Fatalf("recovered connection cannot restart: %+v, %v", got, err)
			}
			if _, err := os.Lstat(filepath.Join(base, legacyConnectionFilename)); !os.IsNotExist(err) {
				t.Fatal("recovery retained plaintext")
			}
		}
	}
}

func TestCiphertextTakesPrecedenceOverLegacyConnection(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDelivery(cfg, base, "test").observeIP("203.0.113.8"); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(base, legacyConnectionFilename)
	if err := os.WriteFile(legacy, []byte(`{"version":2,"master":["192.0.2.7"],"observed_ip":"203.0.113.7"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := BootstrapConfig(Config{}, base, "")
	if err != nil || got.masters[0] != "192.0.2.8:55556" || got.reportedIP() != "203.0.113.8" {
		t.Fatalf("plaintext replaced authoritative ciphertext: %+v, %v", got, err)
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatal("interrupted migration did not clean up plaintext")
	}
}

func TestDamagedCiphertextDoesNotFallBackToPlaintext(t *testing.T) {
	valid, err := sealed.EncryptConfig([]byte(`{"version":2,"master":["192.0.2.8"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, damaged := range [][]byte{
		[]byte(`{"version":2,"master":["192.0.2.8"]}`),
		valid[:len(valid)/2],
		bytes.Repeat([]byte("x"), maxEncryptedConnectionBytes+1),
	} {
		base := t.TempDir()
		if err := os.WriteFile(filepath.Join(base, ConnectionFilename), damaged, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, legacyConnectionFilename), []byte(`{"version":2,"master":["192.0.2.7"]}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := BootstrapConfig(Config{}, base, ""); err == nil {
			t.Fatal("damaged ciphertext accepted or bypassed with plaintext")
		}
		cfg, err := BootstrapConfig(Config{}, base, "192.0.2.9")
		if err != nil {
			t.Fatal(err)
		}
		if err := NewConfigDelivery(cfg, base, "test").persistConnectionSettings(); err != nil {
			t.Fatal(err)
		}
		if settings := decryptSavedConnection(t, base); settings.Master[0] != "192.0.2.9:55556" {
			t.Fatal("explicit Master did not repair ciphertext")
		}
	}
}

func TestInitialConnectionSavePreservesNewerDiscoveredIdentity(t *testing.T) {
	base := t.TempDir()
	stale, err := BootstrapConfig(Config{}, base, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := BootstrapConfig(Config{}, base, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDelivery(fresh, base, "test").observeIP("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDelivery(stale, base, "test").persistConnectionSettings(); err != nil {
		t.Fatal(err)
	}
	if settings := decryptSavedConnection(t, base); settings.ObservedIP != "203.0.113.50" || stale.reportedIP() != settings.ObservedIP {
		t.Fatal("stale initial save replaced discovered identity")
	}
	unchanged, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil || !bytes.Equal(ciphertext, unchanged) {
		t.Fatal("unchanged Master unnecessarily rewrote its ciphertext")
	}
	changed, err := BootstrapConfig(Config{}, base, "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewConfigDelivery(changed, base, "test").persistConnectionSettings(); err != nil {
		t.Fatal(err)
	}
	if settings := decryptSavedConnection(t, base); settings.Master[0] != "192.0.2.8:55556" || settings.ObservedIP != "203.0.113.50" {
		t.Fatal("explicit Master override was not persisted or lost discovered identity")
	}
}

func TestConnectionMigrationRechecksCiphertextAfterWaitingForWriter(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, legacyConnectionFilename)
	if err := os.WriteFile(legacy, []byte(`{"version":2,"master":["192.0.2.7"],"observed_ip":"203.0.113.7"}`), 0600); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockService(filepath.Join(base, ConnectionFilename))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	result := make(chan struct {
		cfg Config
		err error
	}, 1)
	go func() {
		cfg, err := BootstrapConfig(Config{}, base, "")
		result <- struct {
			cfg Config
			err error
		}{cfg, err}
	}()
	select {
	case got := <-result:
		t.Fatalf("migration bypassed the concurrent writer's lock: %+v, %v", got.cfg, got.err)
	case <-time.After(50 * time.Millisecond):
	}
	// Model another process finishing migration and discovery while this
	// process waits. Only ciphertext gets committed under the held lock.
	if err := writeConnectionSettings(base, connectionSettings{Version: 2, Master: []string{"192.0.2.8:55556"}, ObservedIP: "203.0.113.8"}); err != nil {
		t.Fatal(err)
	}
	unlock()
	select {
	case got := <-result:
		if got.err != nil || got.cfg.masters[0] != "192.0.2.8:55556" || got.cfg.reportedIP() != "203.0.113.8" {
			t.Fatalf("migration overwrote the concurrent writer's ciphertext: %+v, %v", got.cfg, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("migration did not resume after the writer released its lock")
	}
}

func TestConnectionPersistenceFailureDoesNotPublishDiscoveredIdentity(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, ConnectionFilename), 0700); err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(cfg, base, "test")
	if err := d.observeIP("203.0.113.8"); err == nil || cfg.reportedIP() != "" {
		t.Fatal("failed connection save published an identity that cannot survive restart")
	}
}

func decryptSavedConnection(t *testing.T, base string) connectionSettings {
	t.Helper()
	ciphertext, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil {
		t.Fatal(err)
	}
	data, err := sealed.DecryptConfig(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var settings connectionSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	return settings
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
