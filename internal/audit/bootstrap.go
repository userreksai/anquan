package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"anqu/internal/defaults"
	"anqu/internal/sealed"
)

const ConnectionFilename = "agent.connection.age"
const legacyConnectionFilename = "agent.connection.json"
const maxConnectionBytes = 64 << 10
const maxEncryptedConnectionBytes = 128 << 10

// Serialize read/modify/write operations within one process. A short directory
// lock additionally serializes migrations and writes across agent processes.
var connectionSettingsMu sync.Mutex

type connectionSettings struct {
	Version    int      `json:"version"`
	Master     []string `json:"master,omitempty"`
	ObservedIP string   `json:"observed_ip,omitempty"`
	Server     []string `json:"server,omitempty"`   // v1 migration only
	AgentIP    string   `json:"agent_ip,omitempty"` // ignored v1 manual identity
}

// BootstrapConfig applies deployment connection settings to a local config.
// With no local config, it creates a transport-only agent waiting for assignment.
// Master accepts comma-separated IPs or DNS hostnames, optionally with a TCP
// port (default 55556). An agent waiting for assignment uses the deployment
// default when no Master is explicit/saved. YAML server is a separate list of
// UDP report destinations and is never overridden here.
func BootstrapConfig(local Config, baseDir, master string) (Config, error) {
	c := local
	stored, err := loadConnectionSettings(baseDir)
	if err != nil {
		if strings.TrimSpace(master) == "" {
			return Config{}, err
		}
		stored = connectionSettings{}
	}
	if c.OutputDir == "" {
		c = Config{
			OutputDir: baseDir, StateFile: "state/md5.json", Timezone: "Asia/Shanghai",
			Setup:            &SetupConfig{Logs: "logs/时间anquan.log", Prom: "textfile/process_monitor.prom", IntervalSeconds: 300},
			waitingForConfig: true,
		}
	}
	c.AgentIP = ""
	c.identity = &agentIdentity{}
	if ip := net.ParseIP(stored.ObservedIP); ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() {
		value := ip.String()
		c.identity.ip.Store(&value)
	}
	c.masters = append([]string(nil), stored.Master...)
	if strings.TrimSpace(master) != "" {
		c.masters = strings.Split(master, ",")
	} else if c.waitingForConfig && len(c.masters) == 0 {
		c.masters = []string{defaults.MasterAddress}
	}
	seen := map[string]bool{}
	for i, address := range c.masters {
		address, err := normalizeEndpoint(address, ConfigDeliveryPort)
		if err != nil || seen[address] {
			return Config{}, fmt.Errorf("invalid or duplicate configuration Master address")
		}
		c.masters[i], seen[address] = address, true
	}
	return normalizeConfig(c, baseDir, nativePathRules())
}

// Automatically retained connection settings let a later no-argument check
// find its master without requiring a user-provided local audit config.
func loadConnectionSettings(baseDir string) (connectionSettings, error) {
	connectionSettingsMu.Lock()
	defer connectionSettingsMu.Unlock()
	settings, legacy, err := readConnectionSettings(baseDir)
	if err != nil {
		return connectionSettings{}, err
	}
	if !legacy {
		return settings, removeLegacyConnectionSettings(baseDir)
	}
	unlock, err := lockConnectionSettings(baseDir)
	if err != nil {
		return connectionSettings{}, err
	}
	defer unlock()
	// Another process may have completed migration or observed a newer IP
	// while this process was waiting. Re-read before committing anything.
	settings, legacy, err = readConnectionSettings(baseDir)
	if err != nil {
		return connectionSettings{}, err
	}
	if legacy {
		err = writeConnectionSettings(baseDir, settings)
	} else {
		err = removeLegacyConnectionSettings(baseDir)
	}
	return settings, err
}

func readConnectionSettings(baseDir string) (connectionSettings, bool, error) {
	data, err := readConnectionFile(filepath.Join(baseDir, ConnectionFilename), maxEncryptedConnectionBytes)
	if err == nil {
		plaintext, err := sealed.DecryptConfig(data)
		if err != nil {
			return connectionSettings{}, false, invalidConnectionSettings()
		}
		defer clear(plaintext)
		settings, err := decodeConnectionSettings(plaintext)
		if err != nil {
			return connectionSettings{}, false, err
		}
		// Ciphertext remains authoritative after an interrupted migration.
		return settings, false, nil
	}
	if !os.IsNotExist(err) {
		return connectionSettings{}, false, invalidConnectionSettings()
	}
	data, err = readConnectionFile(filepath.Join(baseDir, legacyConnectionFilename), maxConnectionBytes)
	if os.IsNotExist(err) {
		return connectionSettings{}, false, nil
	}
	if err != nil {
		return connectionSettings{}, false, invalidConnectionSettings()
	}
	defer clear(data)
	settings, err := decodeConnectionSettings(data)
	if err != nil {
		return connectionSettings{}, false, err
	}
	return settings, true, nil
}

func readConnectionFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, invalidConnectionSettings()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, invalidConnectionSettings()
	}
	return data, nil
}

func invalidConnectionSettings() error {
	return errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
}

func decodeConnectionSettings(data []byte) (connectionSettings, error) {
	if len(data) > maxConnectionBytes {
		return connectionSettings{}, invalidConnectionSettings()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings connectionSettings
	if err := decoder.Decode(&settings); err != nil || (settings.Version != 1 && settings.Version != 2) {
		return connectionSettings{}, invalidConnectionSettings()
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return connectionSettings{}, invalidConnectionSettings()
	}
	if settings.Version == 1 {
		settings.Master = nil
		for _, endpoint := range settings.Server {
			host, _, err := net.SplitHostPort(endpoint)
			if err != nil {
				return connectionSettings{}, invalidConnectionSettings()
			}
			settings.Master = append(settings.Master, net.JoinHostPort(host, ConfigDeliveryPort))
		}
		// A manually supplied v1 IP must not masquerade as discovered identity.
		settings.ObservedIP = ""
	}
	seen := make(map[string]bool)
	for i, endpoint := range settings.Master {
		address, err := normalizeEndpoint(endpoint, ConfigDeliveryPort)
		if err != nil || seen[address] {
			return connectionSettings{}, invalidConnectionSettings()
		}
		settings.Master[i], seen[address] = address, true
	}
	settings.Version, settings.Server, settings.AgentIP = 2, nil, ""
	if ip := net.ParseIP(settings.ObservedIP); ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		settings.ObservedIP = ""
	} else {
		settings.ObservedIP = ip.String()
	}
	return settings, nil
}

func (d *ConfigDelivery) persistConnectionSettings() error {
	if len(d.bootstrap.masters) == 0 {
		return nil
	}
	connectionSettingsMu.Lock()
	defer connectionSettingsMu.Unlock()
	unlock, err := lockConnectionSettings(d.baseDir)
	if err != nil {
		return err
	}
	defer unlock()
	// A startup copy may predate a discovery made by an earlier run. Preserve
	// the saved identity when the Master list is unchanged instead of writing
	// the stale copy over it. Active discovery always commits its new value.
	stored, legacy, err := readConnectionSettings(d.baseDir)
	if err == nil && !legacy && stored.Version == 2 && slices.Equal(stored.Master, d.bootstrap.masters) {
		if stored.ObservedIP != "" && d.bootstrap.identity != nil {
			value := stored.ObservedIP
			d.bootstrap.identity.ip.Store(&value)
		}
		return removeLegacyConnectionSettings(d.baseDir)
	}
	return writeConnectionSettings(d.baseDir, connectionSettings{Version: 2, Master: d.bootstrap.masters, ObservedIP: d.bootstrap.reportedIP()})
}

func (d *ConfigDelivery) persistObservedConnection(ip string) error {
	connectionSettingsMu.Lock()
	defer connectionSettingsMu.Unlock()
	unlock, err := lockConnectionSettings(d.baseDir)
	if err != nil {
		return err
	}
	defer unlock()
	return writeConnectionSettings(d.baseDir, connectionSettings{Version: 2, Master: d.bootstrap.masters, ObservedIP: ip})
}

func lockConnectionSettings(baseDir string) (func(), error) {
	deadline := time.Now().Add(time.Second)
	for {
		unlock, err := lockService(filepath.Join(baseDir, ConnectionFilename))
		if err == nil {
			return unlock, nil
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("cannot lock saved Master connection settings")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Called only while holding the connection settings directory lock. Temporary
// files and the committed file contain ciphertext; plaintext stays in memory.
func writeConnectionSettings(baseDir string, settings connectionSettings) error {
	data, err := json.Marshal(connectionSettings{Version: 2, Master: settings.Master, ObservedIP: settings.ObservedIP})
	if err != nil || len(data) > maxConnectionBytes {
		return errors.New("Master connection settings exceed 64 KiB")
	}
	defer clear(data)
	ciphertext, err := sealed.EncryptConfig(data)
	if err != nil || len(ciphertext) > maxEncryptedConnectionBytes {
		return errors.New("cannot encrypt Master connection settings")
	}
	if err := atomicWrite(filepath.Join(baseDir, ConnectionFilename), ciphertext, 0600); err != nil {
		return errors.New("cannot persist Master connection settings")
	}
	return removeLegacyConnectionSettings(baseDir)
}

func removeLegacyConnectionSettings(baseDir string) error {
	path := filepath.Join(baseDir, legacyConnectionFilename)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0) {
		return errors.New("cannot remove obsolete plaintext Master connection settings")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.New("cannot remove obsolete plaintext Master connection settings")
	}
	return nil
}
