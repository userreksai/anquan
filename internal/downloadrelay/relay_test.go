package downloadrelay

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testMaster struct {
	listener  net.Listener
	targets   map[string]string
	denied    bool
	requests  atomic.Int32
	closed    chan struct{}
	pipelined bool
}

func newTestMaster(t *testing.T, targets map[string]string) *testMaster {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &testMaster{listener: ln, targets: targets, closed: make(chan struct{}, 1)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handle(c)
		}
	}()
	return m
}

func (m *testMaster) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var request frame
	if json.Unmarshal(line, &request) != nil {
		return
	}
	response := frame{Version: 1, Type: "error", Error: "authentication rejected"}
	if request.IP != "172.22.0.11" {
		json.NewEncoder(c).Encode(response)
		return
	}
	switch request.Type {
	case "package_session":
		if !m.denied && request.Token == "control-secret" {
			response = frame{Version: 1, Type: "package_session", Token: "lease-secret", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
		}
		json.NewEncoder(c).Encode(response)
	case "package_close":
		if request.Token == "lease-secret" {
			select {
			case m.closed <- struct{}{}:
			default:
			}
		}
		json.NewEncoder(c).Encode(frame{Version: 1, Type: "package_closed"})
	case "package_relay":
		if request.Token != "lease-secret" {
			json.NewEncoder(c).Encode(response)
			return
		}
		m.requests.Add(1)
		if m.pipelined {
			io.WriteString(c, "{\"version\":1,\"type\":\"package_ready\"}\nHTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nPACKAGES")
			http.ReadRequest(r)
			return
		}
		address := m.targets[request.Target]
		if address == "" {
			json.NewEncoder(c).Encode(response)
			return
		}
		upstream, err := net.Dial("tcp", address)
		if err != nil {
			return
		}
		defer upstream.Close()
		json.NewEncoder(c).Encode(frame{Version: 1, Type: "package_ready"})
		done := make(chan struct{})
		go func() { io.Copy(upstream, r); upstream.Close(); close(done) }()
		io.Copy(c, upstream)
		c.Close()
		<-done
	}
}

func proxyClient(t *testing.T, master *testMaster) (*State, *Proxy, *http.Client) {
	t.Helper()
	state := New()
	state.Update(master.listener.Addr().String(), "172.22.0.11", "control-secret")
	p, err := state.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	u, _ := url.Parse(p.URL())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(u)
	t.Cleanup(transport.CloseIdleConnections)
	return state, p, &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestHTTPAndHTTPSUseMasterRelay(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential leaked")
		}
		io.WriteString(w, "package:"+r.URL.Path)
	}))
	defer origin.Close()
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified TLS package") }))
	defer tlsOrigin.Close()
	m := newTestMaster(t, map[string]string{"packages.test:80": strings.TrimPrefix(origin.URL, "http://"), "example.com:443": strings.TrimPrefix(tlsOrigin.URL, "https://")})
	_, p, client := proxyClient(t, m)
	client.Transport.(*http.Transport).TLSClientConfig = tlsOrigin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	for address, want := range map[string]string{"http://packages.test/a.deb": "package:/a.deb", "https://example.com/a.tar.gz": "verified TLS package"} {
		r, err := client.Get(address)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != want {
			t.Fatalf("got %q want %q", b, want)
		}
	}
	if m.requests.Load() != 2 {
		t.Fatalf("master tunnels=%d", m.requests.Load())
	}
	p.Close()
	select {
	case <-m.closed:
	case <-time.After(time.Second):
		t.Fatal("session not closed")
	}
}

func TestBufferedMasterBytesArePreserved(t *testing.T) {
	m := newTestMaster(t, nil)
	m.pipelined = true
	_, _, client := proxyClient(t, m)
	r, err := client.Get("http://packages.test/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if string(b) != "PACKAGES" {
		t.Fatalf("lost buffered bytes: %q", b)
	}
}

func TestRejectedIdentityDoesNotFallBack(t *testing.T) {
	state := New()
	state.Update("127.0.0.1:1", "172.22.0.11", "")
	if _, err := state.Start(context.Background()); err == nil {
		t.Fatal("old master accepted without control credential")
	}
	m := newTestMaster(t, nil)
	m.denied = true
	_, _, client := proxyClient(t, m)
	r, err := client.Get("http://packages.test/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "authentication rejected") {
		t.Fatalf("status=%d body=%s", r.StatusCode, b)
	}
	if m.requests.Load() != 0 {
		t.Fatal("unauthenticated tunnel opened")
	}
}

func TestControlDisconnectCancelsActiveDownload(t *testing.T) {
	started := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer origin.Close()
	m := newTestMaster(t, map[string]string{"packages.test:80": strings.TrimPrefix(origin.URL, "http://")})
	state, _, client := proxyClient(t, m)
	done := make(chan struct{})
	go func() {
		r, _ := client.Get("http://packages.test/blocked")
		if r != nil {
			r.Body.Close()
		}
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("download never started")
	}
	state.Clear()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("download was not canceled")
	}
	select {
	case <-m.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled session not closed")
	}
}

func TestProxyRejectsWriteMethodsAndOtherPorts(t *testing.T) {
	m := newTestMaster(t, nil)
	_, _, client := proxyClient(t, m)
	for _, tc := range []struct {
		method, address string
		status          int
	}{{"POST", "http://packages.test/a", 405}, {"GET", "http://packages.test:22/a", 400}} {
		req, _ := http.NewRequest(tc.method, tc.address, nil)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.address, r.StatusCode)
		}
	}
	if m.requests.Load() != 0 {
		t.Fatal("invalid request reached master")
	}
}
