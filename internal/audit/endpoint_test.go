package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"anqu/internal/sealed"
)

func TestNormalizeEndpointSupportsDomainsAndExistingIPForms(t *testing.T) {
	for _, tc := range []struct{ address, port, want string }{
		{"sa.sa.ops.tw", "55556", "sa.sa.ops.tw:55556"},
		{"SA.SA.OPS.TW:055555", "55556", "sa.sa.ops.tw:55555"},
		{" sa.sa.ops.tw ", "55555", "sa.sa.ops.tw:55555"},
		{"sa.sa.ops.tw.:55556", "55555", "sa.sa.ops.tw.:55556"},
		{"not-yet-resolvable.invalid", "55556", "not-yet-resolvable.invalid:55556"},
		{"localhost", "55555", "localhost:55555"},
		{"192.0.2.7", "55556", "192.0.2.7:55556"},
		{"192.0.2.7:55557", "55556", "192.0.2.7:55557"},
		{"2001:db8::7", "55556", "[2001:db8::7]:55556"},
		{"[2001:0db8::7]:55555", "55556", "[2001:db8::7]:55555"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			got, err := normalizeEndpoint(tc.address, tc.port)
			if err != nil || got != tc.want {
				t.Fatalf("normalizeEndpoint(%q, %q) = %q, %v; want %q", tc.address, tc.port, got, err, tc.want)
			}
		})
	}
	for _, address := range []string{
		"", " ", ":55556", "sa.sa.ops.tw:", "sa.sa.ops.tw:0", "sa.sa.ops.tw:65536", "sa.sa.ops.tw:+55556", "sa.sa.ops.tw:tcp",
		"http://sa.sa.ops.tw/", "https://sa.sa.ops.tw:55556", "sa.sa.ops.tw/path", "sa.sa.ops.tw?query", "sa.sa.ops.tw#fragment", "user@sa.sa.ops.tw",
		"sa..ops.tw", "-sa.ops.tw", "sa-.ops.tw", "sa_sa.ops.tw", "sa sa.ops.tw", "[sa.sa.ops.tw]:55556", "sa.sa.ops.tw:55556:1",
		".", "127.0.0.999", "999.1.1.1", "0.0.0.0", "0.0.0.0:55556", "::", "[::]:55556", "224.0.0.1", "ff02::1",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a",
	} {
		t.Run("invalid/"+address, func(t *testing.T) {
			if got, err := normalizeEndpoint(address, "55556"); err == nil {
				t.Fatalf("invalid endpoint %q accepted as %q", address, got)
			}
		})
	}
}

func TestEndpointValidationDoesNotResolveDNS(t *testing.T) {
	previous := net.DefaultResolver
	var lookups atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("DNS must not be used during validation")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	if _, err := BootstrapConfig(Config{}, t.TempDir(), "not-yet-resolvable.invalid"); err != nil {
		t.Fatalf("offline DNS blocked bootstrap: %v", err)
	}
	if _, err := ParseConfig([]byte("output_dir: local\nserver: [not-yet-resolvable.invalid]\nlogin: {enabled: false}\nsetup: {logs: logs/agent.log, prom: textfile/agent.prom}\n"), t.TempDir()); err != nil {
		t.Fatalf("offline DNS blocked UDP configuration: %v", err)
	}
	if lookups.Load() != 0 {
		t.Fatal("validation attempted DNS resolution")
	}
}

func TestDomainTCPDialAndAssignedUDPKeepHostnamesAndObservedIdentity(t *testing.T) {
	base := t.TempDir()
	cfg, err := BootstrapConfig(Config{}, base, "sa.sa.ops.tw")
	if err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(cfg, base, "test")
	dialed := false
	d.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = true
		if network != "tcp" || address != "sa.sa.ops.tw:55556" {
			t.Fatalf("dial received %q %q", network, address)
		}
		return nil, errors.New("master offline")
	}
	if _, err := d.Sync(context.Background()); err != nil || !dialed {
		t.Fatalf("domain was not passed to TCP dialer: %v", err)
	}
	if err := d.observeIP("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealed.EncryptConfig([]byte("output_dir: assigned\nserver: [SA.SA.OPS.TW, reports.example.invalid:12345]\nlogin: {enabled: false}\nsetup: {logs: logs/agent.log, prom: textfile/agent.prom}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.accept(configFrame{Version: 1, Type: "config", Revision: configRevision(ciphertext), Ciphertext: string(ciphertext)}, commitAssignment); err != nil {
		t.Fatal(err)
	}
	if d.current.Server[0] != "sa.sa.ops.tw:55555" || d.current.Server[1] != "reports.example.invalid:12345" || d.endpoints[0].tcp != "sa.sa.ops.tw:55556" || d.current.reportedIP() != "203.0.113.9" {
		t.Fatalf("domain assignment changed TCP/identity or resolved UDP hosts: %+v", d.current)
	}
	for _, servers := range []string{
		"sa.sa.ops.tw,SA.SA.OPS.TW:55555",
		"http://sa.sa.ops.tw/",
		"sa.sa.ops.tw:65536",
	} {
		if err := ValidateEmbeddedYAML([]byte("server: ["+servers+"]\n"), "linux"); err == nil {
			t.Fatalf("invalid/duplicate UDP hosts accepted: %s", servers)
		}
	}
}

func TestUDPHeartbeatThroughHostnamePreservesObservedIdentity(t *testing.T) {
	// A wildcard UDP socket receives the IPv4/IPv6 loopback address selected
	// by the system resolver, whose localhost preference can vary by platform.
	listener, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, port, err := net.SplitHostPort(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := net.JoinHostPort("localhost", port)
	cfg, err := ParseConfig([]byte(fmt.Sprintf("output_dir: local\nserver: [%s]\nlogin: {enabled: false}\nsetup: {logs: logs/agent.log, prom: textfile/agent.prom}\n", endpoint)), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ip := "203.0.113.9"
	cfg.identity = &agentIdentity{}
	cfg.identity.ip.Store(&ip)
	results := NotifyHeartbeat(cfg, "domain-test")
	if len(results) != 1 || results[0].Error != "" || results[0].Server != endpoint || results[0].Sent != 1 || results[0].IP != ip {
		t.Fatalf("UDP hostname send failed or changed identity: %+v", results)
	}
	if packet := readHeartbeatPacket(t, listener); packet.Type != "heartbeat" || packet.IP != ip {
		t.Fatalf("UDP domain heartbeat changed automatic identity: %+v", packet)
	}
}
