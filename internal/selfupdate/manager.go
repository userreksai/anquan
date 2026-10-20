package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	mu                             sync.Mutex
	busy                           bool
	current, executable, directory string
	dial                           func(context.Context, string, string) (net.Conn, error)
	launch                         func(context.Context, string) error
	probe                          func(context.Context, string) ([]byte, error)
}

// NewInstalled returns nil for one-shot, non-root, non-systemd or nonstandard
// deployments. Only main's -service path calls it.
func NewInstalled(executable, current string) *Manager {
	if !platformEligible(executable) {
		return nil
	}
	if err := ensurePrivateDirectory(stateDirectory); err != nil {
		return nil
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	m := &Manager{current: current, executable: executable, directory: stateDirectory, dial: dialer.DialContext, launch: launchHelper, probe: probeVersion}
	m.recoverInterruptedStartup()
	return m
}

func (m *Manager) Pin(endpoint, encoded string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("Master did not provide a valid update signing key")
	}
	digest := sha256.Sum256([]byte(endpoint))
	path := filepath.Join(m.directory, "master-"+hex.EncodeToString(digest[:])+".pub")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() != ed25519.PublicKeySize || !privatePermissions(info.Mode()) {
			return nil, errors.New("unsafe pinned update signing key")
		}
		stored, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(stored, key) {
			return nil, errors.New("Master update signing key changed; administrator must verify and reset the pin")
		}
		return ed25519.PublicKey(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, err = file.Write(key)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return nil, closeErr
	}
	if err := syncDirectory(m.directory); err != nil {
		return nil, err
	}
	return ed25519.PublicKey(key), nil
}

// Start returns immediately. The worker belongs to the control connection;
// cancellation interrupts downloads, but a launched systemd helper is detached.
func (m *Manager) Start(ctx context.Context, endpoint, ip string, key ed25519.PublicKey, offer Descriptor, report func(Result) error) error {
	if err := Verify(offer, key, m.current, runtime.GOOS, runtime.GOARCH, time.Now()); err != nil {
		return err
	}
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return errors.New("another Agent update is in progress")
	}
	if state, err := readJournal(m.directory); err == nil && (state.Status == "restarting" || state.Status == "queued") {
		m.mu.Unlock()
		return errors.New("previous Agent update has not completed")
	} else if err != nil && !os.IsNotExist(err) {
		m.mu.Unlock()
		return err
	}
	m.busy = true
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); m.busy = false; m.mu.Unlock() }()
		if err := m.install(ctx, endpoint, ip, offer, report); err != nil {
			_ = report(Result{JobID: offer.JobID, Status: "failed", Error: boundedError(err)})
		}
	}()
	return nil
}

func boundedError(err error) string {
	message := strings.ToValidUTF8(err.Error(), "?")
	if len(message) > 2000 {
		message = message[:2000]
	}
	return message
}

func (m *Manager) install(ctx context.Context, endpoint, ip string, offer Descriptor, report func(Result) error) error {
	archive, stage := filepath.Join(m.directory, "download.tar.gz"), filepath.Join(m.directory, "candidate")
	_ = os.Remove(archive)
	_ = os.Remove(stage)
	defer os.Remove(archive)
	launched := false
	defer func() {
		if !launched {
			_ = os.Remove(stage)
		}
	}()
	if err := report(Result{JobID: offer.JobID, Status: "downloading"}); err != nil {
		return err
	}
	if err := download(ctx, m.dial, endpoint, ip, offer, archive); err != nil {
		return err
	}
	if err := extract(archive, stage, offer); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	output, err := m.probe(probeCtx, stage)
	cancel()
	if err != nil || !versionOutputMatches(output, offer.Version) {
		return errors.New("staged Agent version validation failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oldHash, err := hashFile(m.executable)
	if err != nil {
		return err
	}
	if err := copyExecutable(m.executable, filepath.Join(m.directory, "backup")); err != nil {
		return err
	}
	if err := copyExecutable(m.executable, filepath.Join(m.directory, "helper")); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.directory, "helper-started")); err != nil && !os.IsNotExist(err) {
		return err
	}
	state := journal{JobID: offer.JobID, Version: offer.Version, PreviousVersion: m.current, BinarySHA256: offer.BinarySHA256, PreviousSHA256: oldHash, Status: "staged"}
	if err := writeJournal(m.directory, state); err != nil {
		return err
	}
	if err := report(Result{JobID: offer.JobID, Status: "restarting"}); err != nil {
		state.Status = "failed"
		state.Error = boundedError(err)
		_ = writeJournal(m.directory, state)
		return err
	}
	state.Status = "queued"
	if err := writeJournal(m.directory, state); err != nil {
		return err
	}
	if err := m.launch(ctx, filepath.Join(m.directory, "journal.json")); err != nil {
		state.Status = "failed"
		state.Error = boundedError(err)
		_ = writeJournal(m.directory, state)
		return fmt.Errorf("start detached update helper: %w", err)
	}
	launched = true
	// Normally stopping agent.service cancels this connection immediately.
	// If stopping fails, the old process stays online and must report the
	// helper's persisted error without waiting for a later reconnect.
	timer := time.NewTimer(75 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return errors.New("update helper did not stop the old Agent within the handoff deadline")
		case <-ticker.C:
			state, err := readJournal(m.directory)
			if err == nil && state.JobID == offer.JobID && (state.Status == "failed" || state.Status == "rolled_back") {
				return report(Result{JobID: state.JobID, Status: state.Status, Error: state.Error})
			}
		}
	}
}

func versionOutputMatches(output []byte, version string) bool {
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[0] != "anqu" {
		return false
	}
	actual, err := parseVersion(fields[1])
	if err != nil {
		return false
	}
	expected, err := parseVersion(version)
	return err == nil && actual == expected
}

// IdentityResult reports an existing outcome. A new binary is not marked ready
// until it has re-established its Master identity and passed its own digest check.
func (m *Manager) IdentityResult(confirm bool) (*Result, string) {
	state, err := readJournal(m.directory)
	if err != nil {
		return nil, ""
	}
	digest, err := hashFile(m.executable)
	if err != nil {
		return nil, ""
	}
	if state.Status == "restarting" {
		if digest == state.BinarySHA256 && strings.TrimPrefix(m.current, "v") == strings.TrimPrefix(state.Version, "v") {
			if !confirm {
				return &Result{JobID: state.JobID, Status: "restarting"}, digest
			}
			state.Status = "applied"
			if err := writeJournal(m.directory, state); err != nil {
				return nil, digest
			}
		} else {
			return nil, digest
		}
	}
	if state.Status == "applied" && digest != state.BinarySHA256 {
		return nil, digest
	}
	if state.Status == "rolled_back" && digest != state.PreviousSHA256 {
		return nil, digest
	}
	if state.Status != "applied" && state.Status != "rolled_back" && state.Status != "failed" {
		return nil, digest
	}
	return &Result{JobID: state.JobID, Status: state.Status, Error: state.Error}, digest
}

// A fresh service start can classify an interrupted handoff after a reboot or
// helper failure. A running old process reconnecting never runs this path.
func (m *Manager) recoverInterruptedStartup() {
	state, err := readJournal(m.directory)
	if err != nil || (state.Status != "queued" && state.Status != "restarting" && state.Status != "staged") {
		return
	}
	digest, err := hashFile(m.executable)
	if err != nil || digest != state.PreviousSHA256 || updateHelperActive(state.JobID) {
		return
	}
	state.Status = "rolled_back"
	state.Error = "update was interrupted; service restarted with the preserved Agent"
	_ = writeJournal(m.directory, state)
}
