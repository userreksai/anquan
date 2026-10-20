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
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"anqu/internal/downloadrelay"
	"anqu/internal/sealed"
	"anqu/internal/selfupdate"
)

const ConfigDeliveryPort = "55556"
const maxConfigFrameBytes = 8 << 20

type configFrame struct {
	Version            int                    `json:"version"`
	Type               string                 `json:"type"`
	IP                 string                 `json:"ip,omitempty"`
	ReportedIP         string                 `json:"reported_ip,omitempty"`
	Host               string                 `json:"host,omitempty"`
	AgentVersion       string                 `json:"agent_version,omitempty"`
	DiscoverIP         bool                   `json:"discover_ip,omitempty"`
	Revision           string                 `json:"revision,omitempty"`
	Ciphertext         string                 `json:"ciphertext,omitempty"`
	Error              string                 `json:"error,omitempty"`
	DownloadRelay      bool                   `json:"download_relay,omitempty"`
	DownloadToken      string                 `json:"download_token,omitempty"`
	Token              string                 `json:"token,omitempty"`
	Target             string                 `json:"target,omitempty"`
	ExpiresAt          string                 `json:"expires_at,omitempty"`
	SelfUpdate         bool                   `json:"self_update,omitempty"`
	GOOS               string                 `json:"goos,omitempty"`
	GOARCH             string                 `json:"goarch,omitempty"`
	UpdatePublicKey    string                 `json:"update_public_key,omitempty"`
	Update             *selfupdate.Descriptor `json:"update,omitempty"`
	UpdateJobID        string                 `json:"update_job_id,omitempty"`
	UpdateBinarySHA256 string                 `json:"update_binary_sha256,omitempty"`
	UpdateResult       *selfupdate.Result     `json:"update_result,omitempty"`
}

type controlEndpoint struct{ tcp string }

// configUpdate is acknowledged only after the service has acquired any new
// state lock, committed the encrypted cache and activated the new workers.
type configUpdate struct {
	config Config
	commit func() error
	result chan error
}

// ConfigDelivery uses deployment TCP addresses independently of YAML's UDP
// destinations, and identifies the local interface used to reach the master.
// The first reachable master owns the connection until it disconnects.
type ConfigDelivery struct {
	bootstrap   Config
	current     Config
	baseDir     string
	version     string
	revision    string
	endpoints   []controlEndpoint
	dial        func(context.Context, string, string) (net.Conn, error)
	retry       time.Duration
	ping        time.Duration
	selfUpdater *selfupdate.Manager
}

// SetSelfUpdater is called only by the installed continuous service. One-shot
// synchronization never advertises or accepts executable updates.
func (d *ConfigDelivery) SetSelfUpdater(updater *selfupdate.Manager) { d.selfUpdater = updater }

func NewConfigDelivery(bootstrap Config, baseDir, version string) *ConfigDelivery {
	if bootstrap.identity == nil {
		bootstrap.identity = &agentIdentity{}
	}
	if len(bootstrap.masters) > 0 && bootstrap.downloadRelay == nil {
		bootstrap.downloadRelay = downloadrelay.New()
	}
	d := &ConfigDelivery{bootstrap: bootstrap, current: bootstrap, baseDir: baseDir, version: version, retry: 5 * time.Second, ping: 30 * time.Second}
	dialer := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	d.dial = dialer.DialContext
	seen := make(map[string]bool)
	for _, address := range bootstrap.masters {
		if !seen[address] {
			d.endpoints = append(d.endpoints, controlEndpoint{address})
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
	// The UDP server list belongs to the assigned config. TCP configuration
	// destinations and observed identity belong to deployment/runtime state.
	cfg.masters, cfg.identity, cfg.downloadRelay = d.bootstrap.masters, d.bootstrap.identity, d.bootstrap.downloadRelay
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
	unlock, err := lockService(d.cachePath())
	if err != nil {
		return d.current, errors.New("another service or check controls master configuration synchronization")
	}
	defer unlock()
	if err := d.persistConnectionSettings(); err != nil {
		return d.current, err
	}
	for _, endpoint := range d.endpoints {
		conn, err := d.dial(ctx, "tcp", endpoint.tcp)
		if err != nil {
			continue
		}
		err = d.connection(ctx, conn, endpoint, true, func(cfg Config, commit func() error) error {
			// A one-shot scan must not acknowledge a component assignment
			// without executing the service's transactional activation path.
			if cfg.Security != nil || d.current.Security != nil {
				return errors.New("security component assignments require -service mode")
			}
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

func (d *ConfigDelivery) observeIP(address string) error {
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("master returned an invalid observed agent IP")
	}
	value := ip.String()
	if err := d.persistObservedConnection(value); err != nil {
		return err
	}
	if d.bootstrap.identity == nil {
		return errors.New("agent identity was not initialized")
	}
	d.bootstrap.identity.localIP.Store(nil)
	d.bootstrap.identity.ip.Store(&value)
	return nil
}

func (d *ConfigDelivery) selectLocalIP(address string) error {
	value := usableLocalIP(net.ParseIP(address))
	if value == "" {
		return errors.New("agent socket has no usable local IP")
	}
	if d.bootstrap.identity == nil {
		return errors.New("agent identity was not initialized")
	}
	if err := d.persistLocalConnection(value); err != nil {
		return err
	}
	d.bootstrap.identity.localIP.Store(&value)
	d.bootstrap.identity.ip.Store(&value)
	return nil
}

func (d *ConfigDelivery) connection(ctx context.Context, conn net.Conn, endpoint controlEndpoint, once bool, apply func(Config, func() error) error) error {
	if d.bootstrap.downloadRelay != nil {
		defer d.bootstrap.downloadRelay.Clear()
	}
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
	selectedIP := localSocketIP(conn.LocalAddr())
	hello := configFrame{Version: 1, Type: "hello", DiscoverIP: true, Host: host, AgentVersion: d.version, DownloadRelay: true}
	updater := d.selfUpdater
	if !once && updater != nil {
		hello.SelfUpdate = true
		hello.GOOS, hello.GOARCH = runtime.GOOS, runtime.GOARCH
		result, digest := updater.IdentityResult(false)
		if result != nil {
			hello.UpdateJobID, hello.UpdateBinarySHA256 = result.JobID, digest
			if result.Status != "restarting" {
				hello.UpdateResult = result
			}
		}
	} else {
		updater = nil
	}
	if selectedIP != "" {
		if err := d.selectLocalIP(selectedIP); err != nil {
			return err
		}
		// Legacy masters already accept explicit hello.ip when discovery is
		// disabled. reported_ip allows new masters to acknowledge local mode.
		hello.IP, hello.ReportedIP, hello.DiscoverIP = selectedIP, selectedIP, false
	}
	if err := write(hello); err != nil {
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
	var updateKey []byte
	var updateKeyError error
	var observedIP string
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
		case "identity":
			if selectedIP != "" {
				if ip := net.ParseIP(frame.IP); ip == nil || ip.String() != selectedIP {
					return errors.New("master returned an identity different from the selected local IP")
				}
			} else if err := d.observeIP(frame.IP); err != nil {
				return err
			}
			if d.bootstrap.downloadRelay != nil {
				d.bootstrap.downloadRelay.Update(endpoint.tcp, frame.IP, frame.DownloadToken)
			}
			observedIP = frame.IP
			if updater != nil && frame.UpdatePublicKey != "" {
				updateKey, updateKeyError = updater.Pin(endpoint.tcp, frame.UpdatePublicKey)
				if result, digest := updater.IdentityResult(updateKeyError == nil); updateKeyError == nil && result != nil && result.Status != "restarting" {
					if err := write(configFrame{Version: 1, Type: "update_result", AgentVersion: d.version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, UpdateJobID: result.JobID, UpdateBinarySHA256: digest, UpdateResult: result}); err != nil {
						return err
					}
				}
			}
		case "update_offer":
			if updater == nil || frame.Update == nil || observedIP == "" {
				return errors.New("unavailable or unauthenticated Agent update offer")
			}
			report := func(result selfupdate.Result) error {
				return write(configFrame{Version: 1, Type: "update_status", UpdateJobID: result.JobID, UpdateResult: &result})
			}
			if len(updateKey) == 0 {
				message := "Master update signing key is unavailable"
				if updateKeyError != nil {
					message = updateKeyError.Error()
				}
				if err := report(selfupdate.Result{JobID: frame.Update.JobID, Status: "failed", Error: message}); err != nil {
					return err
				}
				continue
			}
			if err := updater.Start(ctx, endpoint.tcp, observedIP, updateKey, *frame.Update, report); err != nil {
				if err := report(selfupdate.Result{JobID: frame.Update.JobID, Status: "failed", Error: boundedConfigACKError(err.Error())}); err != nil {
					return err
				}
			}
		case "pong":
			continue
		case "config":
			applyErr := d.accept(frame, apply)
			ack := configFrame{Version: 1, Type: "ack", Revision: frame.Revision}
			if applyErr != nil {
				ack.Error = boundedConfigACKError(applyErr.Error())
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

// Keep the final apt/dnf error visible without exceeding the master's ACK limit.
// Full command output remains in the local security_apply_failed log.
func boundedConfigACKError(value string) string {
	value = strings.ToValidUTF8(value, "�")
	const limit = 4096
	if len(value) <= limit {
		return value
	}
	const prefix = "[truncated; see Agent security_apply_failed log] ... "
	value = value[len(value)-(limit-len(prefix)):]
	for !utf8.ValidString(value) {
		value = value[1:]
	}
	return prefix + value
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
