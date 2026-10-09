package audit

import (
	"encoding/json"
	"fmt"
	"os"

	"anqu/internal/sealed"
)

type baselineSession struct {
	prepared  bool
	committed map[string]bool
}

// NewSession starts a new agent lifetime. The first complete file/process scan
// becomes its baseline; subsequent scans compare with the last committed scan.
// Login cursors survive restarts. Call once per process, never on every tick.
func NewSession(c Config) Config {
	c.session = &baselineSession{committed: make(map[string]bool)}
	return c
}

func readBaseline(c Config, path, kind string, target any) error {
	if c.session != nil && !c.session.committed[kind] {
		return os.ErrNotExist
	}
	return readState(path, kind, target)
}

func readState(path, kind string, target any) error {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data, err := sealed.OpenState(ciphertext, kind)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer clear(data)
	return decodeJSON(path, data, target)
}

func writeState(path, kind string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	return writeEncryptedState(path, kind, data)
}

func writeEncryptedState(path, kind string, data []byte) error {
	ciphertext, err := sealed.SealState(data, kind)
	if err != nil {
		return err
	}
	// The temporary file also contains ciphertext only.
	return atomicWrite(path, ciphertext, 0600)
}

// Called under the scan lock, once per process. Protect all legacy state files,
// including disabled modules, without resetting login cursors or leaving a
// plaintext backup. Collection still validates the decrypted state afterwards.
func prepareSession(c Config) error {
	if c.session == nil || c.session.prepared {
		return nil
	}
	for _, item := range []struct{ suffix, kind string }{
		{"", "md5"}, {".files", "files"}, {".processes", "processes"}, {".logins", "login"},
	} {
		path := c.StateFile + item.suffix
		if err := protectLegacyState(path, item.kind); err != nil {
			return fmt.Errorf("encrypt existing state %s: %w", path, err)
		}
	}
	c.session.prepared = true
	return nil
}

func protectLegacyState(path, kind string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("state must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	if sealed.IsState(data) {
		return nil
	}
	return writeEncryptedState(path, kind, data)
}
