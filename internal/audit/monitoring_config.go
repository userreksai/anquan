package audit

import (
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SetupConfig struct {
	Logs            string `json:"logs" yaml:"logs"`
	Prom            string `json:"prom" yaml:"prom"`
	IntervalSeconds int    `json:"interval_seconds" yaml:"interval_seconds"`
}

func (c Config) MonitoringMode() bool {
	return c.FilesMonitoring != nil || c.ProcessMonitoring != nil || c.Setup != nil || len(c.Server) > 0
}

func (c Config) Interval() time.Duration {
	if c.Setup == nil {
		return 5 * time.Minute
	}
	return time.Duration(c.Setup.IntervalSeconds) * time.Second
}

func normalizeMonitoring(c *Config, base string, rules pathRules) error {
	if c.AgentIP != "" {
		ip := net.ParseIP(c.AgentIP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("agent_ip must be a unicast IPv4 or IPv6 address")
		}
		c.AgentIP = ip.String()
	}
	if !c.MonitoringMode() {
		return nil
	}
	if c.Setup == nil {
		c.Setup = &SetupConfig{}
	}
	if c.Setup.Logs == "" {
		c.Setup.Logs = "/var/log/时间anquan.log"
	}
	if c.Setup.Prom == "" {
		c.Setup.Prom = "/var/lib/node_exporter/textfile_collector/时间process_monitor.prom"
	}
	if c.Setup.IntervalSeconds == 0 {
		c.Setup.IntervalSeconds = 300
	}
	if c.Setup.IntervalSeconds < 1 || c.Setup.IntervalSeconds > 86400 {
		return fmt.Errorf("setup.interval_seconds must be 1..86400")
	}
	for _, item := range []struct {
		name   string
		value  *string
		suffix string
	}{{"logs", &c.Setup.Logs, ".log"}, {"prom", &c.Setup.Prom, ".prom"}} {
		if strings.TrimSpace(*item.value) == "" {
			return fmt.Errorf("setup.%s cannot be blank", item.name)
		}
		if !strings.HasSuffix(*item.value, item.suffix) {
			*item.value = strings.TrimRight(*item.value, "/\\") + "/时间" + map[string]string{"logs": "anquan.log", "prom": "process_monitor.prom"}[item.name]
		}
		var err error
		*item.value, err = rules.resolve(base, *item.value)
		if err != nil {
			return fmt.Errorf("setup.%s: %w", item.name, err)
		}
		// Tokens belong in filenames, never directories: rotation and exclusions remain bounded.
		parent := path.Dir(strings.ReplaceAll(*item.value, "\\", "/"))
		if strings.Contains(parent, "时间") || strings.ContainsAny(parent, "{}") {
			return fmt.Errorf("setup.%s: timestamp tokens must be in filename", item.name)
		}
		if item.name == "logs" && strings.Contains(*item.value, "{time}") {
			return fmt.Errorf("setup.logs uses daily {date} or 时间, not {time}")
		}
		remaining := strings.NewReplacer("{date}", "", "{time}", "").Replace(*item.value)
		if strings.ContainsAny(remaining, "{}") {
			return fmt.Errorf("setup.%s has an unknown timestamp token", item.name)
		}
	}
	seen := map[string]bool{}
	for _, endpoint := range c.Server {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("server entry must be an IP:port (IPv6 in brackets): %q", endpoint)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid UDP port: %q", endpoint)
		}
		if seen[endpoint] {
			return fmt.Errorf("duplicate server: %q", endpoint)
		}
		seen[endpoint] = true
	}
	if err := normalizeFilesMonitoring(c.FilesMonitoring, base, rules); err != nil {
		return err
	}
	if err := normalizeProcessMonitoring(c.ProcessMonitoring); err != nil {
		return err
	}
	return nil
}

var beijing = time.FixedZone("Asia/Shanghai", 8*60*60)

func datedOutput(template string, now time.Time, daily bool) string {
	now = now.In(beijing)
	stamp := now.Format("20060102_150405.000000000-0700")
	if daily {
		stamp = now.Format("20060102")
	}
	name := filepath.Base(template)
	if !strings.Contains(name, "时间") && !strings.Contains(name, "{date}") && !strings.Contains(name, "{time}") {
		name = stamp + "_" + name
	} else {
		name = strings.NewReplacer("时间", stamp, "{time}", stamp, "{date}", now.Format("20060102")).Replace(name)
		// Every task must create its own .prom, even a date-only template.
		if !daily && !strings.Contains(template, "时间") && !strings.Contains(template, "{time}") {
			name = stamp + "_" + name
		}
	}
	return filepath.Join(filepath.Dir(template), name)
}

func monitoringExcluded(c Config, p string) bool {
	if excluded(c, p) || strings.HasPrefix(p, c.StateFile+".") {
		return true
	}
	if c.Setup == nil {
		return false
	}
	for i, template := range []string{c.Setup.Logs, c.Setup.Prom} {
		if filepath.Clean(filepath.Dir(p)) != filepath.Clean(filepath.Dir(template)) {
			continue
		}
		if outputNamePattern(template, i == 0).MatchString(filepath.Base(p)) {
			return true
		}
		if strings.HasPrefix(filepath.Base(p), ".anqu-") && strings.HasSuffix(p, ".tmp") {
			return true
		}
	}
	return false
}

// Only reserve generated filenames, not every file with a matching suffix.
// In particular, /var/log/other-anquan.log must still be monitored.
func outputNamePattern(template string, daily bool) *regexp.Regexp {
	name := filepath.Base(template)
	stamp := `[0-9]{8}_[0-9]{6}\.[0-9]{9}\+0800`
	if daily {
		stamp = `[0-9]{8}`
	}
	pattern := regexp.QuoteMeta(name)
	if !strings.Contains(name, "时间") && !strings.Contains(name, "{time}") && !strings.Contains(name, "{date}") {
		pattern = stamp + "_" + pattern
	} else {
		pattern = strings.NewReplacer("时间", stamp, regexp.QuoteMeta("{time}"), stamp, regexp.QuoteMeta("{date}"), `[0-9]{8}`).Replace(pattern)
		if !daily && !strings.Contains(name, "时间") && !strings.Contains(name, "{time}") {
			pattern = stamp + "_" + pattern
		}
	}
	return regexp.MustCompile("^" + pattern + "$")
}
