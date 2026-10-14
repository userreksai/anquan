package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"anqu/internal/sealed"
)

type localAddressConn struct {
	net.Conn
	address net.Addr
}

func (c localAddressConn) LocalAddr() net.Addr { return c.address }

func TestLocalSocketIdentityRejectsUnusableAddressesAndCanonicalizes(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    string
	}{
		{"172.22.0.27", "172.22.0.27"},
		{"::ffff:172.22.0.27", "172.22.0.27"},
		{"2001:db8:0:0::27", "2001:db8::27"},
		{"fd00::27", "fd00::27"},
		{"", ""}, {"invalid", ""}, {"0.0.0.0", ""}, {"::", ""},
		{"127.0.0.1", ""}, {"::1", ""}, {"169.254.1.2", ""},
		{"fe80::27", ""}, {"224.0.0.1", ""}, {"ff02::1", ""}, {"255.255.255.255", ""},
	} {
		for _, address := range []net.Addr{
			&net.TCPAddr{IP: net.ParseIP(tc.address), Port: 54321},
			&net.UDPAddr{IP: net.ParseIP(tc.address), Port: 54321},
		} {
			if got := localSocketIP(address); got != tc.want {
				t.Errorf("localSocketIP(%q) = %q, want %q", tc.address, got, tc.want)
			}
		}
	}
	for _, address := range []net.Addr{nil, (*net.TCPAddr)(nil), (*net.UDPAddr)(nil), &net.IPAddr{IP: net.ParseIP("172.22.0.27")}} {
		if got := localSocketIP(address); got != "" {
			t.Errorf("unsupported address produced a local socket identity: %q", got)
		}
	}
}

func TestRetainedLocalIPv4AndIPv6MustStillBelongToMachine(t *testing.T) {
	interfaces := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.22.0.27"), Mask: net.CIDRMask(24, 32)},
		&net.IPAddr{IP: net.ParseIP("2001:db8::27")},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPAddr{IP: net.ParseIP("fe80::27")},
	}
	for _, tc := range []struct{ address, want string }{
		{"172.22.0.27", "172.22.0.27"}, {"::ffff:172.22.0.27", "172.22.0.27"},
		{"2001:db8:0:0::27", "2001:db8::27"},
		{"172.22.240.6", ""}, {"2001:db8::28", ""}, {"127.0.0.1", ""}, {"fe80::27", ""}, {"bad", ""},
	} {
		if got := retainedLocalIP(tc.address, interfaces); got != tc.want {
			t.Errorf("retainedLocalIP(%q) = %q, want %q", tc.address, got, tc.want)
		}
	}
	if got := retainedLocalIP("172.22.0.27", nil); got != "" {
		t.Fatal("a cached address was accepted with no local interfaces")
	}
}

func TestTCPRouteIdentityRegistersWithOldAndNewMasters(t *testing.T) {
	for _, tc := range []struct {
		name, route, acknowledgement, want string
	}{
		{"legacy IPv4 master", "::ffff:172.22.0.27", "", "172.22.0.27"},
		{"acknowledged IPv4", "172.22.0.27", "::ffff:172.22.0.27", "172.22.0.27"},
		{"acknowledged IPv6", "2001:db8::27", "2001:db8:0:0::27", "2001:db8::27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, base := deliveryBootstrap(t)
			d := NewConfigDelivery(cfg, base, "local-test")
			d.ping = time.Hour
			agent, master := net.Pipe()
			defer master.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- d.connection(ctx, localAddressConn{agent, &net.TCPAddr{IP: net.ParseIP(tc.route), Port: 54321}}, d.endpoints[0], true, commitAssignment)
			}()
			_ = master.SetDeadline(time.Now().Add(3 * time.Second))
			decoder := json.NewDecoder(master)
			var hello configFrame
			if err := decoder.Decode(&hello); err != nil || hello.Type != "hello" || hello.DiscoverIP || hello.IP != tc.want || hello.ReportedIP != tc.want {
				t.Fatalf("local registration is incompatible with legacy hello semantics: %+v, %v", hello, err)
			}
			settings := decryptSavedConnection(t, base)
			if cfg.reportedIP() != tc.want || settings.Version != 3 || settings.LocalIP != tc.want || settings.ObservedIP != "" {
				t.Fatalf("local IP was not saved and published before hello: %+v", settings)
			}
			if tc.acknowledgement != "" {
				if err := json.NewEncoder(master).Encode(configFrame{Version: 1, Type: "identity", IP: tc.acknowledgement}); err != nil {
					t.Fatal(err)
				}
			}
			if err := json.NewEncoder(master).Encode(configFrame{Version: 1, Type: "config"}); err != nil {
				t.Fatal(err)
			}
			var ack configFrame
			if err := decoder.Decode(&ack); err != nil || ack.Type != "ack" || ack.Error != "" {
				t.Fatalf("legacy/no-identity or acknowledged local handshake did not accept config: %+v %v", ack, err)
			}
			if err := <-done; err != nil || cfg.reportedIP() != tc.want {
				t.Fatalf("local identity changed after Master response: %q %v", cfg.reportedIP(), err)
			}
		})
	}
}

func TestMasterCannotOverwriteSelectedLocalIPWithRelayIdentity(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	d := NewConfigDelivery(cfg, base, "local-test")
	agent, master := net.Pipe()
	defer master.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- d.connection(ctx, localAddressConn{agent, &net.TCPAddr{IP: net.ParseIP("172.22.0.27")}}, d.endpoints[0], true, commitAssignment)
	}()
	_ = master.SetDeadline(time.Now().Add(3 * time.Second))
	var hello configFrame
	if err := json.NewDecoder(master).Decode(&hello); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(master).Encode(configFrame{Version: 1, Type: "identity", IP: "172.22.240.6"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("a relay identity was accepted: %v", err)
	}
	if cfg.reportedIP() != "172.22.0.27" || decryptSavedConnection(t, base).LocalIP != "172.22.0.27" {
		t.Fatal("Master response overwrote the machine's chosen local identity")
	}
}

func TestFirstUDPRouteIsSharedAcrossDestinationsAndThenTCPOverrides(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	var workers sync.WaitGroup
	results := make(chan string, 40)
	for i := 0; i < cap(results); i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			address := "172.22.0.27"
			if i%2 != 0 {
				address = "172.22.0.28"
			}
			results <- cfg.udpReportedIP(&net.UDPAddr{IP: net.ParseIP(address)})
		}(i)
	}
	workers.Wait()
	close(results)
	selected := cfg.reportedIP()
	if selected != "172.22.0.27" && selected != "172.22.0.28" {
		t.Fatalf("no valid first UDP route selected: %q", selected)
	}
	for value := range results {
		if value != selected {
			t.Fatal("parallel UDP workers selected different machine identities")
		}
	}
	if _, err := os.Stat(filepath.Join(base, ConnectionFilename)); !os.IsNotExist(err) {
		t.Fatal("temporary UDP route identity unexpectedly created persistent settings")
	}
	first, second := heartbeatListener(t), heartbeatListener(t)
	cfg.Server = []string{first.LocalAddr().String(), second.LocalAddr().String()}
	if results := NotifyHeartbeat(cfg, "test"); len(results) != 2 || results[0].IP != selected || results[1].IP != selected {
		t.Fatalf("UDP destinations did not share the chosen identity: %+v", results)
	}
	if readHeartbeatPacket(t, first).IP != selected || readHeartbeatPacket(t, second).IP != selected {
		t.Fatal("heartbeat payload lost the shared local identity")
	}
	d := NewConfigDelivery(cfg, base, "test")
	if err := d.selectLocalIP("172.22.0.29"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.udpReportedIP(&net.UDPAddr{IP: net.ParseIP("172.22.0.30")}); got != "172.22.0.29" {
		t.Fatal("TCP selection did not replace the temporary UDP identity")
	}
}

func TestEncryptedV2ObservedRelayMigratesWithoutPoisoningIdentity(t *testing.T) {
	base := t.TempDir()
	data, err := sealed.EncryptConfig([]byte(`{"version":2,"master":["sa.sa.ops.tw"],"observed_ip":"172.22.240.6","local_ip":"172.22.240.6"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, ConnectionFilename), data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := BootstrapConfig(Config{}, base, "")
	if err != nil || cfg.reportedIP() != "" || cfg.localIP() != "" || cfg.masters[0] != "sa.sa.ops.tw:55556" {
		t.Fatalf("old observed relay was restored as local machine identity: %+v %v", cfg, err)
	}
	settings := decryptSavedConnection(t, base)
	if settings.Version != 3 || settings.LocalIP != "" || settings.ObservedIP != "172.22.240.6" {
		t.Fatalf("v2 migration did not separate local and observed metadata: %+v", settings)
	}
}

func TestHistoryUsesTheSameLocalIPAsOtherUDPWorkers(t *testing.T) {
	cfg, _ := deliveryBootstrap(t)
	selected := cfg.udpReportedIP(&net.UDPAddr{IP: net.ParseIP("172.22.0.27")})
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg.Server = []string{listener.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sendHistoryEventsContext(ctx, cfg, []historyEvent{{ID: "local-history", Type: "command_history", Time: time.Now(), Data: json.RawMessage(`{"command":"test"}`)}})
	}()
	_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
	data := make([]byte, 60000)
	n, source, err := listener.ReadFromUDP(data)
	if err != nil {
		t.Fatal(err)
	}
	var event udpEnvelope
	if err := json.Unmarshal(data[:n], &event); err != nil || event.IP != selected || !event.AckRequested {
		t.Fatalf("history did not share the first UDP-route identity: %+v %v", event, err)
	}
	ack, _ := json.Marshal(map[string]any{"version": 1, "type": "ack", "event_id": event.EventID})
	if _, err := listener.WriteToUDP(ack, source); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestValidLocalIPCacheSurvivesRestartAndStaleCacheIsIgnored(t *testing.T) {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	local := ""
	for _, address := range interfaces {
		if network, ok := address.(*net.IPNet); ok {
			local = usableLocalIP(network.IP)
			if local != "" {
				break
			}
		}
	}
	if local == "" {
		t.Skip("host has no usable local interface address")
	}
	cfg, base := deliveryBootstrap(t)
	staleStartup, err := BootstrapConfig(Config{}, base, cfg.masters[0])
	if err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(cfg, base, "test")
	if err := d.selectLocalIP(local); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(base, ConnectionFilename))
	if err != nil || bytes.Contains(first, []byte(local)) {
		t.Fatal("local identity persistence is missing or exposes plaintext")
	}
	if err := NewConfigDelivery(staleStartup, base, "test").persistConnectionSettings(); err != nil || staleStartup.reportedIP() != local {
		t.Fatalf("stale startup failed to preserve the newer locally assigned identity: %q %v", staleStartup.reportedIP(), err)
	}
	if unchanged, err := os.ReadFile(filepath.Join(base, ConnectionFilename)); err != nil || !bytes.Equal(first, unchanged) {
		t.Fatal("stale startup replaced the newer encrypted local identity")
	}
	restored, err := BootstrapConfig(Config{}, base, "")
	if err != nil || restored.reportedIP() != local || restored.localIP() != local {
		t.Fatalf("valid locally assigned cached IP did not survive restart: %q %v", restored.reportedIP(), err)
	}
	stale := "203.0.113.231"
	if retainedLocalIP(stale, interfaces) != "" {
		t.Skip("test stale address is configured on this host")
	}
	if err := writeConnectionSettings(base, connectionSettings{Version: 3, Master: cfg.masters, LocalIP: stale, ObservedIP: "172.22.240.6"}); err != nil {
		t.Fatal(err)
	}
	restored, err = BootstrapConfig(Config{}, base, "")
	if err != nil || restored.reportedIP() != "" || restored.localIP() != "" {
		t.Fatal("an address removed from local interfaces was restored")
	}
}

func TestLocalIdentityPersistenceFailureDoesNotPublish(t *testing.T) {
	cfg, base := deliveryBootstrap(t)
	if err := os.Mkdir(filepath.Join(base, ConnectionFilename), 0700); err != nil {
		t.Fatal(err)
	}
	d := NewConfigDelivery(cfg, base, "test")
	if err := d.selectLocalIP("172.22.0.27"); err == nil || cfg.reportedIP() != "" || cfg.localIP() != "" {
		t.Fatal("a failed encrypted save published the local machine identity")
	}
}
