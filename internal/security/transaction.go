package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"anqu/internal/sealed"
)

type managedFile struct {
	Data []byte      `json:"data"`
	Mode os.FileMode `json:"mode"`
}
type snapshot struct {
	Path   string      `json:"path"`
	Exists bool        `json:"exists"`
	Data   []byte      `json:"data,omitempty"`
	Mode   os.FileMode `json:"mode"`
}
type manifest struct {
	Files map[string]string `json:"files"`
	// Identical pre-existing files may be used, but are never owned by us.
	// They must not be overwritten or deleted on a later configuration change.
	ReferencedFiles            map[string]string `json:"referenced_files,omitempty"`
	Options                    []string          `json:"options,omitempty"`
	AuditKeys                  []string          `json:"audit_keys,omitempty"`
	Sysctl                     map[string]string `json:"sysctl,omitempty"`
	SysctlOriginal             map[string]string `json:"sysctl_original,omitempty"`
	CtrlAltDelMasked           bool              `json:"ctrl_alt_del_masked"`
	CtrlAltDelOriginallyMasked bool              `json:"ctrl_alt_del_originally_masked"`
	Firewall                   bool              `json:"firewall"`
	AppliedAt                  *time.Time        `json:"applied_at,omitempty"`
}

func (m manifest) configuredFiles() map[string]string {
	files := make(map[string]string, len(m.Files)+len(m.ReferencedFiles))
	for p, hash := range m.ReferencedFiles {
		files[p] = hash
	}
	for p, hash := range m.Files {
		files[p] = hash
	}
	return files
}

type transactionJournal struct {
	Before   []snapshot      `json:"before"`
	Previous manifest        `json:"previous"`
	Next     manifest        `json:"next"`
	Dirty    map[string]bool `json:"dirty,omitempty"`
}
type transaction struct {
	manager  *Manager
	before   []snapshot
	touched  map[string]bool
	previous manifest
	next     manifest
	dirty    map[string]bool
}

func (m *Manager) journalPath() string {
	return filepath.Join(m.OutputDir, "security-transaction.state")
}
func (m *Manager) manifestPath() string { return filepath.Join(m.OutputDir, "security-managed.state") }
func writePrivateJSON(path, kind string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	b, err = sealed.SealState(b, kind)
	if err != nil {
		return err
	}
	return atomicFile(path, b, 0600)
}
func readPrivateJSON(path, kind string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b, err = sealed.OpenState(b, kind)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}
func atomicFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".anquan-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return nil
}
func noSymlink(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing managed path through symlink: %s", p)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if parent := filepath.Dir(p); parent == p {
			break
		}
	}
	return nil
}
func (t *transaction) change(p string, next *managedFile) error {
	full := t.manager.path(p)
	if err := noSymlink(full); err != nil {
		return err
	}
	if !t.touched[p] {
		s := snapshot{Path: p}
		info, err := os.Stat(full)
		if err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("managed file is not regular: %s", p)
			}
			if info.Size() > 8*1024*1024 {
				return fmt.Errorf("managed file exceeds backup limit: %s", p)
			}
			s.Exists = true
			s.Mode = info.Mode().Perm()
			s.Data, err = os.ReadFile(full)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		t.before = append(t.before, s)
		t.touched[p] = true
		if err := t.save(); err != nil {
			return err
		}
	}
	if next == nil {
		err := os.Remove(full)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Config directories must remain traversable by the system service. Private
	// state uses 0700; managed system directories follow ordinary 0755.
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	return atomicFile(full, next.Data, next.Mode)
}
func (t *transaction) save() error {
	return writePrivateJSON(t.manager.journalPath(), "security-transaction", transactionJournal{Before: t.before, Previous: t.previous, Next: t.next, Dirty: t.dirty})
}
func (m *Manager) restore(snapshots []snapshot) error {
	var errs []error
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		full := m.path(s.Path)
		if err := noSymlink(full); err != nil {
			errs = append(errs, err)
			continue
		}
		var err error
		if s.Exists {
			err = atomicFile(full, s.Data, s.Mode)
		} else {
			err = os.Remove(full)
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (m *Manager) loadManifest() (manifest, error) {
	v := manifest{Files: map[string]string{}}
	err := readPrivateJSON(m.manifestPath(), "security-managed", &v)
	if os.IsNotExist(err) {
		return v, nil
	}
	return v, err
}
func sortedKeys[V any](v map[string]V) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
