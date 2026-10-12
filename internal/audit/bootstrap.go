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
	Version int      `json:"version"`
	Server  []string `json:"server"`
	AgentIP string   `json:"agent_ip,omitempty"`
}

// BootstrapConfig applies deployment connection settings to a local config.
// With no local config, it creates a transport-only agent waiting for assignment.
// Master accepts comma-separated IPs or IP:UDP-port; TCP always uses 55556.
func BootstrapConfig(local Config, baseDir, master, agentIP string) (Config, error) {
	c := local
	if c.OutputDir == "" {
		stored, err := loadConnectionSettings(baseDir)
		if err != nil && strings.TrimSpace(master) == "" {
			return Config{}, err
		}
		c = Config{
			OutputDir: baseDir, StateFile: "state/md5.json", Timezone: "Asia/Shanghai",
			Setup:            &SetupConfig{Logs: "logs/时间anquan.log", Prom: "textfile/process_monitor.prom", IntervalSeconds: 300},
			Server:           stored.Server,
			AgentIP:          stored.AgentIP,
			waitingForConfig: true,
		}
	}
	if strings.TrimSpace(master) != "" {
		c.Server = nil
		for _, address := range strings.Split(master, ",") {
			address = strings.TrimSpace(address)
			if ip := net.ParseIP(address); ip != nil {
				address = net.JoinHostPort(ip.String(), "55555")
			}
			c.Server = append(c.Server, address)
		}
	}
	if strings.TrimSpace(agentIP) != "" {
		c.AgentIP = strings.TrimSpace(agentIP)
	}
	if c.waitingForConfig && len(c.Server) == 0 {
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
	if err := decoder.Decode(&settings); err != nil || settings.Version != 1 {
		return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return connectionSettings{}, errors.New("invalid saved Master connection settings; specify -master or ANQUAN_MASTER")
	}
	return settings, nil
}

func (d *ConfigDelivery) persistConnectionSettings() error {
	if !d.bootstrap.waitingForConfig {
		return nil
	}
	data, err := json.Marshal(connectionSettings{Version: 1, Server: d.bootstrap.Server, AgentIP: d.bootstrap.AgentIP})
	if err != nil || len(data) > 64*1024 {
		return errors.New("Master connection settings exceed 64 KiB")
	}
	if err := atomicWrite(filepath.Join(d.baseDir, ConnectionFilename), data, 0600); err != nil {
		return errors.New("cannot persist Master connection settings")
	}
	return nil
}
