package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"anqu/internal/sealed"
)

const ConfigDeliveryPort = "55556"
const maxConfigFrameBytes = 8 << 20

type configFrame struct {
	Version      int    `json:"version"`
	Type         string `json:"type"`
	IP           string `json:"ip,omitempty"`
	Host         string `json:"host,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	Revision     string `json:"revision,omitempty"`
	Ciphertext   string `json:"ciphertext,omitempty"`
	Error        string `json:"error,omitempty"`
}

type controlEndpoint struct{ tcp, udp string }

// configUpdate is acknowledged only after the service has acquired any new
// state lock, committed the encrypted cache and activated the new workers.
type configUpdate struct {
	config Config
	commit func() error
	result chan error
}

// ConfigDelivery keeps transport and machine identity anchored to config.age.
// The first reachable master owns the connection until it disconnects.
type ConfigDelivery struct {
	bootstrap Config
	current   Config
	baseDir   string
	version   string
	revision  string
	endpoints []controlEndpoint
	dial      func(context.Context, string, string) (net.Conn, error)
	retry     time.Duration
	ping      time.Duration
}

func NewConfigDelivery(bootstrap Config, baseDir, version string) *ConfigDelivery {
	d := &ConfigDelivery{bootstrap: bootstrap, current: bootstrap, baseDir: baseDir, version: version, retry: 5 * time.Second, ping: 30 * time.Second}
	dialer := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	d.dial = dialer.DialContext
	seen := make(map[string]bool)
	for _, endpoint := range bootstrap.Server {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		address := net.JoinHostPort(host, ConfigDeliveryPort)
		if !seen[address] {
			d.endpoints = append(d.endpoints, controlEndpoint{address, endpoint})
			seen[address] = true
		}
	}
	return d
}

func (d *ConfigDelivery) cachePath() string {
	return filepath.Join(d.baseDir, sealed.MasterConfigFilename)
}

// CachedConfig preserves the last valid assignment through a master outage.
// An absent or invalid cache leaves the local bootstrap configuration active.
func (d *ConfigDelivery) CachedConfig() (Config, error) {
	f, err := os.Open(d.cachePath())
	if os.IsNotExist(err) {
		return d.current, nil
	}
	if err != nil {
		return d.current, errors.New("cannot read master configuration cache")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > sealed.MaxEncryptedConfigBytes {
		return d.current, errors.New("master configuration cache is not a bounded regular file")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(f, sealed.MaxEncryptedConfigBytes+1))
	if err != nil {
		return d.current, errors.New("cannot read master configuration cache")
	}
	cfg, err := d.parseAssigned(ciphertext)
	if err != nil {
		return d.current, err
	}
	d.current, d.revision = cfg, configRevision(ciphertext)
	return cfg, nil
}

func configRevision(ciphertext []byte) string {
	digest := sha256.Sum256(ciphertext)
	return hex.EncodeToString(digest[:])
}

func (d *ConfigDelivery) parseAssigned(ciphertext []byte) (Config, error) {
	data, err := sealed.DecryptConfig(ciphertext)
	if err != nil {
		return Config{}, errors.New("master configuration decryption failed")
	}
	defer clear(data)
	cfg, err := decodeYAML(data)
	if err != nil {
		return Config{}, errors.New("master configuration contains invalid YAML")
	}
	// Shared templates cannot alter transport destinations or node identity.
	cfg.Server = append([]string(nil), d.bootstrap.Server...)
	cfg.AgentIP = d.bootstrap.AgentIP
	cfg, err = normalizeConfig(cfg, d.baseDir, nativePathRules())
	if err != nil {
		return Config{}, errors.New("master configuration validation failed")
	}
	return cfg, nil
}

// Sync tries to obtain the current assignment before a single check or service
// startup. Callers bound its context; offline masters retain the cached config.
func (d *ConfigDelivery) Sync(ctx context.Context) (Config, error) {
	if len(d.endpoints) == 0 {
		return d.current, nil
	}
	unlock, err := lockState(d.cachePath() + ".service.lock")
	if err != nil {
		return d.current, errors.New("another service or check controls master configuration synchronization")
	}
	defer unlock()
	for _, endpoint := range d.endpoints {
		conn, err := d.dial(ctx, "tcp", endpoint.tcp)
		if err != nil {
			continue
		}
		err = d.connection(ctx, conn, endpoint, true, func(cfg Config, commit func() error) error {
			if err := commit(); err != nil {
				return err
			}
			d.current = cfg
			return nil
		})
		return d.current, err
	}
	if ctx.Err() != nil {
		return d.current, ctx.Err()
	}
	return d.current, nil
}

func (d *ConfigDelivery) run(ctx context.Context, updates chan<- configUpdate) {
	if len(d.endpoints) == 0 {
		return
	}
	apply := func(cfg Config, commit func() error) error {
		update := configUpdate{cfg, commit, make(chan error, 1)}
		select {
		case updates <- update:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-update.result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for ctx.Err() == nil {
		for _, endpoint := range d.endpoints {
			conn, err := d.dial(ctx, "tcp", endpoint.tcp)
			if err != nil {
				continue
			}
			_ = d.connection(ctx, conn, endpoint, false, apply)
			// Reconsider priority after any disconnect; never run masters in parallel.
			break
		}
		timer := time.NewTimer(d.retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *ConfigDelivery) helloIP(endpoint controlEndpoint) string {
	if d.bootstrap.AgentIP != "" {
		return d.bootstrap.AgentIP
	}
	// Use the existing UDP route, which can differ from a TCP route on machines
	// with policy routing. This matches sendUDP's machine primary key exactly.
	conn, err := net.Dial("udp", endpoint.udp)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func (d *ConfigDelivery) connection(ctx context.Context, conn net.Conn, endpoint controlEndpoint, once bool, apply func(Config, func() error) error) error {
	ctx, cancel := context.WithCancel(ctx)
	var writeMu sync.Mutex
	write := func(frame configFrame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		return json.NewEncoder(conn).Encode(frame)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		_ = conn.Close()
	}()
	defer func() { cancel(); _ = conn.Close(); <-done }()
	host, err := os.Hostname()
	if err != nil {
		return errors.New("cannot determine agent hostname")
	}
	if err := write(configFrame{Version: 1, Type: "hello", IP: d.helloIP(endpoint), Host: host, AgentVersion: d.version}); err != nil {
		return err
	}
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(d.ping)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := write(configFrame{Version: 1, Type: "ping"}); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); _ = conn.Close(); <-pingDone }()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), maxConfigFrameBytes)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := conn.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			return err
		}
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return scanner.Err()
			}
			return io.EOF
		}
		var frame configFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil || frame.Version != 1 {
			return errors.New("invalid master configuration frame")
		}
		switch frame.Type {
		case "pong":
			continue
		case "config":
			applyErr := d.accept(frame, apply)
			ack := configFrame{Version: 1, Type: "ack", Revision: frame.Revision}
			if applyErr != nil {
				ack.Error = applyErr.Error()
			}
			if err := write(ack); err != nil {
				return err
			}
			if once {
				return applyErr
			}
		default:
			return errors.New("unexpected master configuration frame")
		}
	}
}

func (d *ConfigDelivery) accept(frame configFrame, apply func(Config, func() error) error) error {
	if frame.Revision == "" && frame.Ciphertext == "" {
		// Always clear a stale/invalid cache even when local config is active.
		commit := func() error {
			err := os.Remove(d.cachePath())
			if err != nil && !os.IsNotExist(err) {
				return errors.New("cannot remove master configuration cache")
			}
			return nil
		}
		if d.revision == "" {
			return commit()
		}
		if err := apply(d.bootstrap, commit); err != nil {
			return fmt.Errorf("cannot activate local configuration: %w", err)
		}
		d.current, d.revision = d.bootstrap, ""
		return nil
	}
	if frame.Revision == "" || frame.Ciphertext == "" || len(frame.Ciphertext) > sealed.MaxEncryptedConfigBytes || configRevision([]byte(frame.Ciphertext)) != frame.Revision {
		return errors.New("master configuration revision or ciphertext is invalid")
	}
	if frame.Revision == d.revision {
		return nil
	}
	cfg, err := d.parseAssigned([]byte(frame.Ciphertext))
	if err != nil {
		return err
	}
	commit := func() error {
		if err := atomicWrite(d.cachePath(), []byte(frame.Ciphertext), 0600); err != nil {
			return errors.New("cannot persist master configuration cache")
		}
		return nil
	}
	if err := apply(cfg, commit); err != nil {
		return fmt.Errorf("cannot activate master configuration: %w", err)
	}
	d.current, d.revision = cfg, frame.Revision
	return nil
}
