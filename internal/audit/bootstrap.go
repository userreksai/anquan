package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const ConnectionFilename = "agent.connection.json"

type connectionSettings struct {
	Version    int      `json:"version"`
	Master     []string `json:"master,omitempty"`
	ObservedIP string   `json:"observed_ip,omitempty"`
	Server     []string `json:"server,omitempty"`   // v1 migration only
	AgentIP    string   `json:"agent_ip,omitempty"` // ignored v1 manual identity
}

// BootstrapConfig applies deployment connection settings to a local config.
// With no local config, it creates a transport-only agent waiting for assignment.
// Master accepts comma-separated IPs or IP:TCP-port, default 55556. YAML server
// is a separate list of UDP report destinations and is never overridden here.
func BootstrapConfig(local Config, baseDir, master string) (Config, error) {
	c := local
	stored, err := loadConnectionSettings(baseDir)
	if err != nil && strings.TrimSpace(master) == "" {
		return Config{}, err
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
	}
	seen := map[string]bool{}
	for i, address := range c.masters {
		address, err := normalizeEndpoint(address, ConfigDeliveryPort)
		if err != nil || seen[address] {
			return Config{}, fmt.Errorf("invalid or duplicate configuration Master address")
		}
		c.masters[i], seen[address] = address, true
	}
	if c.waitingForConfig && len(c.masters) == 0 {
		return Config{}, fmt.Errorf("no local configuration; specify -master or ANQUAN_MASTER to wait for platform configuration")
	}
	return normalizeConfig(c, baseDir, nativePathRules())
}

// Automatically retained connection settings let a later no-argument check
// find its master without requiring a user-provided local audit config.
func loadConnectionSettings(baseDir string) (connectionSettings, error) {
	f, err := os.Open(filepath.Join(baseDir, ConnectionFilename))
	if os.IsNotExist(err) {
		return connectionSettings{}, nil
	}
	if err != nil {
		return connectionSettings{}, errors.New("cannot read saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 64*1024+1))
	decoder.DisallowUnknownFields()
	var settings connectionSettings
	if err := decoder.Decode(&settings); err != nil || (settings.Version != 1 && settings.Version != 2) {
		return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	if settings.Version == 1 {
		settings.Master = nil
		for _, endpoint := range settings.Server {
			host, _, err := net.SplitHostPort(endpoint)
			if err != nil {
				return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
			}
			settings.Master = append(settings.Master, net.JoinHostPort(host, ConfigDeliveryPort))
		}
		// A manually supplied v1 IP must not masquerade as discovered identity.
		settings.ObservedIP = ""
	}
	return settings, nil
}

func (d *ConfigDelivery) persistConnectionSettings() error {
	if len(d.bootstrap.masters) == 0 {
		return nil
	}
	return d.persistObservedConnection(d.bootstrap.reportedIP())
}

func (d *ConfigDelivery) persistObservedConnection(ip string) error {
	data, err := json.Marshal(connectionSettings{Version: 2, Master: d.bootstrap.masters, ObservedIP: ip})
	if err != nil || len(data) > 64*1024 {
		return errors.New("Master connection settings exceed 64 KiB")
	}
	if err := atomicWrite(filepath.Join(d.baseDir, ConnectionFilename), data, 0600); err != nil {
		return errors.New("cannot persist Master connection settings")
	}
	return nil
}
