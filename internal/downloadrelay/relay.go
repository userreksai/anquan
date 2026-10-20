// Package downloadrelay tunnels package downloads through the connected master.
// Its credentials are runtime-only and never belong to an agent configuration.
package downloadrelay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type frame struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	IP        string `json:"ip,omitempty"`
	Token     string `json:"token,omitempty"`
	Target    string `json:"target,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type identity struct {
	endpoint, ip, token string
	ctx                 context.Context
}

// State is shared by cached and newly assigned configurations. A disconnect
// cancels every outstanding download and erases the old control credential.
type State struct {
	mu      sync.Mutex
	current identity
	cancel  context.CancelFunc
	changed chan struct{}
	known   bool
	dial    func(context.Context, string, string) (net.Conn, error)
}

func New() *State {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &State{changed: make(chan struct{}), dial: d.DialContext}
}

func (s *State) Update(endpoint, ip, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.current, s.cancel, s.known = identity{endpoint, ip, token, ctx}, cancel, true
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *State) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.current = identity{}
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *State) snapshot(ctx context.Context) (identity, error) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		s.mu.Lock()
		id, known, changed := s.current, s.known, s.changed
		s.mu.Unlock()
		if id.ctx != nil {
			if id.token == "" {
				return identity{}, errors.New("master does not provide authenticated package downloads; upgrade the master or install dependencies manually")
			}
			return id, nil
		}
		if known {
			return identity{}, errors.New("master package download connection is offline; direct Internet fallback is disabled")
		}
		select {
		case <-ctx.Done():
			return identity{}, ctx.Err()
		case <-timer.C:
			return identity{}, errors.New("master package download identity is unavailable; direct Internet fallback is disabled")
		case <-changed:
		}
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// Proxy is a short-lived loopback HTTP proxy. The only remotely reachable
// endpoint it dials is the master TCP configuration port.
type Proxy struct {
	state       *State
	id          identity
	ctx         context.Context
	cancel      context.CancelFunc
	listener    net.Listener
	server      *http.Server
	mu          sync.Mutex
	sessionMu   sync.Mutex
	lease       string
	connections map[net.Conn]struct{}
	closed      bool
	once        sync.Once
}

func (s *State) Start(ctx context.Context) (*Proxy, error) {
	id, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(id.ctx, cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	p := &Proxy{state: s, id: id, ctx: ctx, cancel: cancel, listener: ln, connections: make(map[net.Conn]struct{})}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10, ConnState: func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			p.track(c)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			p.untrack(c)
		}
	}}
	go func() { _ = p.server.Serve(ln) }()
	go func() { <-ctx.Done(); stop(); _ = p.Close() }()
	return p, nil
}

func (p *Proxy) URL() string { return "http://" + p.listener.Addr().String() }
func (p *Proxy) track(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
	} else {
		p.connections[c] = struct{}{}
	}
}
func (p *Proxy) untrack(c net.Conn) { p.mu.Lock(); delete(p.connections, c); p.mu.Unlock() }

func (p *Proxy) exchange(ctx context.Context, request frame, expected string) (net.Conn, frame, error) {
	conn, err := p.state.dial(ctx, "tcp", p.id.endpoint)
	if err != nil {
		return nil, frame{}, fmt.Errorf("connect master package relay: %w", err)
	}
	p.track(conn)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request.Version, request.IP = 1, p.id.ip
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		p.untrack(conn)
		conn.Close()
		return nil, frame{}, err
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	line, err := reader.ReadSlice('\n')
	var response frame
	if err == nil {
		err = json.Unmarshal(line, &response)
	}
	if err == nil && (response.Version != 1 || response.Type != expected) {
		message := response.Error
		if message == "" {
			message = "unexpected response"
		}
		err = fmt.Errorf("master package relay denied download: %s", message)
	}
	if err != nil {
		p.untrack(conn)
		conn.Close()
		return nil, frame{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{conn, reader}, response, nil
}

func (p *Proxy) session() (string, error) {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()
	if err := p.ctx.Err(); err != nil {
		return "", err
	}
	if p.lease != "" {
		return p.lease, nil
	}
	c, response, err := p.exchange(p.ctx, frame{Type: "package_session", Token: p.id.token}, "package_session")
	if err != nil {
		return "", err
	}
	p.untrack(c.(*bufferedConn).Conn)
	c.Close()
	if response.Token == "" {
		return "", errors.New("master package relay returned an empty session")
	}
	p.lease = response.Token
	return p.lease, nil
}

func target(host, defaultPort string) (string, error) {
	if host == "" || strings.ContainsAny(host, "/\\@ \t\r\n") {
		return "", errors.New("invalid package target")
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(host, ":") {
			return "", errors.New("package target must use host:80 or host:443")
		}
		name, port = host, defaultPort
	}
	if name == "" || (port != "80" && port != "443") {
		return "", errors.New("package downloads only support TCP 80 and 443")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", err
	}
	return net.JoinHostPort(name, port), nil
}

func (p *Proxy) tunnel(host string) (net.Conn, error) {
	lease, err := p.session()
	if err != nil {
		return nil, err
	}
	c, _, err := p.exchange(p.ctx, frame{Type: "package_relay", Token: lease, Target: host}, "package_ready")
	return c, err
}

func stripHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "package relay only supports GET, HEAD and CONNECT", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Scheme != "http" || r.URL.User != nil {
		http.Error(w, "package HTTP requests must use an absolute HTTP URL", http.StatusBadRequest)
		return
	}
	host, err := target(r.URL.Host, "80")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := p.tunnel(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer c.Close()
	defer p.untrack(c.(*bufferedConn).Conn)
	stop := context.AfterFunc(r.Context(), func() { c.Close() })
	defer stop()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Close = true
	stripHopHeaders(out.Header)
	if err = out.Write(c); err != nil {
		http.Error(w, "master package relay write failed", http.StatusBadGateway)
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(c), out)
	if err != nil {
		http.Error(w, "master package relay response failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	stripHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, err := target(r.Host, "443")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := p.tunnel(host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer c.Close()
	defer p.untrack(c.(*bufferedConn).Conn)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunneling unavailable", http.StatusInternalServerError)
		return
	}
	local, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	p.track(local)
	defer p.untrack(local)
	defer local.Close()
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(c, buffer); c.Close(); close(done) }()
	_, _ = io.Copy(local, c)
	local.Close()
	c.Close()
	<-done
}

func (p *Proxy) Close() error {
	p.once.Do(func() {
		p.cancel()
		_ = p.listener.Close()
		_ = p.server.Close()
		p.mu.Lock()
		p.closed = true
		for c := range p.connections {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.sessionMu.Lock()
		lease := p.lease
		p.lease = ""
		p.sessionMu.Unlock()
		if lease != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Closing a session must work after the installation context expired.
			c, err := p.state.dial(ctx, "tcp", p.id.endpoint)
			if err == nil {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_ = json.NewEncoder(c).Encode(frame{Version: 1, Type: "package_close", IP: p.id.ip, Token: lease})
			}
		}
	})
	return nil
}
