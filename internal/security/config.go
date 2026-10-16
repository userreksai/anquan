// Package security manages optional host collectors and typed Linux policies.
// It never changes the agent transport or exposes another network listener.
package security

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Enabled               bool           `json:"enabled" yaml:"enabled"`
	InstallMissing        bool           `json:"install_missing" yaml:"install_missing"`
	PollIntervalSeconds   int            `json:"poll_interval_seconds" yaml:"poll_interval_seconds"`
	StatusIntervalSeconds int            `json:"status_interval_seconds" yaml:"status_interval_seconds"`
	MaxQueueEvents        int            `json:"max_queue_events" yaml:"max_queue_events"`
	Auditd                AuditdConfig   `json:"auditd" yaml:"auditd"`
	Tetragon              TetragonConfig `json:"tetragon" yaml:"tetragon"`
	Sudo                  SudoConfig     `json:"sudo" yaml:"sudo"`
	Policies              PolicyConfig   `json:"policies" yaml:"policies"`
}
type AuditdConfig struct {
	Enabled    bool     `json:"enabled" yaml:"enabled"`
	AuditExec  bool     `json:"audit_exec" yaml:"audit_exec"`
	WatchPaths []string `json:"watch_paths" yaml:"watch_paths"`
	Rules      []string `json:"rules" yaml:"rules"`
}
type TetragonConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	Version       string `json:"version" yaml:"version"`
	DownloadURL   string `json:"download_url" yaml:"download_url"`
	SHA256        string `json:"sha256" yaml:"sha256"`
	Config        string `json:"config" yaml:"config"`
	TracingPolicy string `json:"tracing_policy" yaml:"tracing_policy"`
}
type SudoConfig struct {
	Enabled         bool        `json:"enabled" yaml:"enabled"`
	IOLogging       bool        `json:"io_logging" yaml:"io_logging"`
	UploadIO        bool        `json:"upload_io" yaml:"upload_io"`
	MaxSessionBytes int         `json:"max_session_bytes" yaml:"max_session_bytes"`
	Grants          []SudoGrant `json:"grants" yaml:"grants"`
}
type SudoGrant struct {
	User     string   `json:"user" yaml:"user"`
	RunAs    string   `json:"run_as" yaml:"run_as"`
	Commands []string `json:"commands" yaml:"commands"`
	NoPasswd bool     `json:"nopasswd" yaml:"nopasswd"`
}
type PolicyConfig struct {
	Mode                  string            `json:"mode" yaml:"mode"`
	SSH                   SSHConfig         `json:"ssh" yaml:"ssh"`
	Sysctl                map[string]string `json:"sysctl" yaml:"sysctl"`
	SessionTimeoutSeconds int               `json:"session_timeout_seconds" yaml:"session_timeout_seconds"`
	DisableCtrlAltDel     bool              `json:"disable_ctrl_alt_del" yaml:"disable_ctrl_alt_del"`
	GRUB                  GRUBConfig        `json:"grub" yaml:"grub"`
}
type SSHConfig struct {
	Enabled                bool     `json:"enabled" yaml:"enabled"`
	PasswordAuthentication string   `json:"password_authentication" yaml:"password_authentication"`
	PermitRootLogin        string   `json:"permit_root_login" yaml:"permit_root_login"`
	AllowUsers             []string `json:"allow_users" yaml:"allow_users"`
	AllowSources           []string `json:"allow_sources" yaml:"allow_sources"`
}
type GRUBConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	PasswordHash string `json:"password_hash" yaml:"password_hash"`
}

func (c *Config) Normalize() {
	if c.Tetragon.Version == "" {
		c.Tetragon.Version = "v1.7.1"
	}
	if c.PollIntervalSeconds == 0 {
		c.PollIntervalSeconds = 2
	}
	if c.StatusIntervalSeconds == 0 {
		c.StatusIntervalSeconds = 30
	}
	if c.MaxQueueEvents == 0 {
		c.MaxQueueEvents = 10000
	}
	if c.Policies.Mode == "" {
		c.Policies.Mode = "audit"
	}
	if c.Sudo.MaxSessionBytes == 0 {
		c.Sudo.MaxSessionBytes = 20 * 1024 * 1024
	}
}

var userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$`)
var sysctlPattern = regexp.MustCompile(`^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_-]+)+$`)
var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)
var optionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func (c Config) Validate() error {
	c.Normalize()
	if c.PollIntervalSeconds < 1 || c.PollIntervalSeconds > 300 {
		return fmt.Errorf("security.poll_interval_seconds must be 1..300")
	}
	if c.StatusIntervalSeconds < 10 || c.StatusIntervalSeconds > 86400 {
		return fmt.Errorf("security.status_interval_seconds must be 10..86400")
	}
	if c.MaxQueueEvents < 100 || c.MaxQueueEvents > 100000 {
		return fmt.Errorf("security.max_queue_events must be 100..100000")
	}
	if c.Sudo.MaxSessionBytes < 1024*1024 || c.Sudo.MaxSessionBytes > 200*1024*1024 {
		return fmt.Errorf("sudo.max_session_bytes must be 1MiB..200MiB")
	}
	if c.Sudo.UploadIO && !c.Sudo.IOLogging {
		return fmt.Errorf("sudo.upload_io requires sudo.io_logging")
	}
	if len(c.Sudo.Grants) > 128 {
		return fmt.Errorf("too many sudo grants")
	}
	for _, g := range c.Sudo.Grants {
		if g.User == "ALL" || g.RunAs == "ALL" {
			return fmt.Errorf("sudo grant user/run_as must name one local account, not ALL")
		}
		if !userPattern.MatchString(g.User) || (g.RunAs != "" && !userPattern.MatchString(g.RunAs)) {
			return fmt.Errorf("sudo grant user/run_as must be local account names")
		}
		if len(g.Commands) == 0 || len(g.Commands) > 64 {
			return fmt.Errorf("sudo grant commands must contain 1..64 entries")
		}
		for _, cmd := range g.Commands {
			if !strings.HasPrefix(cmd, "/") || strings.ContainsAny(cmd, "\r\n\x00,:=\\\"'!#") || len(cmd) > 1024 {
				return fmt.Errorf("sudo command must be an absolute path with literal arguments and no sudoers metacharacters")
			}
			for _, arg := range strings.Fields(cmd) {
				if strings.ContainsAny(arg, "*?[]") {
					return fmt.Errorf("sudo command wildcards are unsupported; provide literal arguments")
				}
			}
		}
	}
	if c.Policies.Mode != "audit" && c.Policies.Mode != "enforce" {
		return fmt.Errorf("security.policies.mode must be audit or enforce")
	}
	if c.Policies.SessionTimeoutSeconds != 0 && (c.Policies.SessionTimeoutSeconds < 60 || c.Policies.SessionTimeoutSeconds > 86400) {
		return fmt.Errorf("security session timeout must be 60..86400 or 0")
	}
	if len(c.Auditd.WatchPaths) > 512 || len(c.Auditd.Rules) > 512 {
		return fmt.Errorf("security auditd has too many paths/rules")
	}
	for _, p := range c.Auditd.WatchPaths {
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, " \t\r\n\x00") || p == "/" {
			return fmt.Errorf("invalid audit watch path %q", p)
		}
	}
	for _, r := range c.Auditd.Rules {
		// Do not permit a remote rule to clear, disable or freeze somebody else's audit policy.
		if strings.ContainsAny(r, "\r\n\x00") || len(r) > 4096 || !(strings.HasPrefix(r, "-a always,exit ") || strings.HasPrefix(r, "-w /")) || !strings.Contains(r, "-k anquan_") {
			return fmt.Errorf("custom audit rule must be a single additive rule with -k anquan_* key")
		}
		for _, token := range strings.Fields(r) {
			if strings.HasPrefix(token, "--") || token == "-D" || token == "-d" || token == "-e" || token == "-f" || token == "-b" || token == "-r" || token == "-R" {
				return fmt.Errorf("custom audit rule cannot change global audit state")
			}
		}
	}
	if len(c.Policies.Sysctl) > 256 {
		return fmt.Errorf("security.policies.sysctl exceeds 256 settings")
	}
	for k, v := range c.Policies.Sysctl {
		if !sysctlPattern.MatchString(k) || strings.ContainsAny(v, "\r\n\x00") || len(v) > 128 || strings.TrimSpace(v) == "" {
			return fmt.Errorf("invalid sysctl setting %q", k)
		}
	}
	s := c.Policies.SSH
	if s.PasswordAuthentication != "" && s.PasswordAuthentication != "yes" && s.PasswordAuthentication != "no" {
		return fmt.Errorf("invalid ssh password_authentication")
	}
	if s.PermitRootLogin != "" && s.PermitRootLogin != "yes" && s.PermitRootLogin != "no" && s.PermitRootLogin != "prohibit-password" {
		return fmt.Errorf("invalid ssh permit_root_login")
	}
	for _, u := range s.AllowUsers {
		if !userPattern.MatchString(u) {
			return fmt.Errorf("invalid ssh user %q", u)
		}
	}
	for _, a := range s.AllowSources {
		if _, err := netip.ParsePrefix(a); err != nil {
			if _, err = netip.ParseAddr(a); err != nil {
				return fmt.Errorf("invalid SSH source %q", a)
			}
		}
	}
	if c.Policies.GRUB.Enabled && c.Policies.Mode == "enforce" && !regexp.MustCompile(`^grub\.pbkdf2\.sha512\.[0-9]+\.[A-Fa-f0-9]+\.[A-Fa-f0-9]+$`).MatchString(c.Policies.GRUB.PasswordHash) {
		return fmt.Errorf("GRUB enforcement requires a grub.pbkdf2.sha512 hash from grub-mkpasswd-pbkdf2")
	}
	t := c.Tetragon
	if t.Version != "" && !versionPattern.MatchString(t.Version) {
		return fmt.Errorf("Tetragon version must be a pinned vX.Y.Z release")
	}
	if t.SHA256 != "" {
		b, e := hex.DecodeString(t.SHA256)
		if e != nil || len(b) != 32 {
			return fmt.Errorf("Tetragon sha256 must have 64 hexadecimal characters")
		}
	}
	if t.DownloadURL != "" {
		u, e := url.Parse(t.DownloadURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("Tetragon download_url must use HTTPS")
		}
		if t.SHA256 == "" && !(u.Host == "github.com" && strings.HasPrefix(u.Path, "/cilium/tetragon/releases/download/")) {
			return fmt.Errorf("custom Tetragon download requires SHA256")
		}
	}
	if len(t.Config) > 256*1024 || len(t.TracingPolicy) > 1024*1024 {
		return fmt.Errorf("Tetragon configuration is too large")
	}
	if _, err := tetragonOptions(t.Config); err != nil {
		return err
	}
	if t.TracingPolicy != "" {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(t.TracingPolicy), &doc); err != nil {
			return fmt.Errorf("invalid tracing_policy YAML: %w", err)
		}
		if doc["kind"] != "TracingPolicy" && doc["kind"] != "TracingPolicyNamespaced" {
			return fmt.Errorf("tracing_policy.kind must be TracingPolicy or TracingPolicyNamespaced")
		}
	}
	return nil
}
func tetragonOptions(raw string) (map[string]string, error) {
	var values map[string]any
	if err := yaml.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("invalid Tetragon config YAML: %w", err)
	}
	result := map[string]string{}
	for k, v := range values {
		if !optionPattern.MatchString(k) {
			return nil, fmt.Errorf("invalid Tetragon option %q", k)
		}
		switch v.(type) {
		case string, bool, int, int64, float64:
		default:
			return nil, fmt.Errorf("Tetragon option %s must be a scalar", k)
		}
		if strings.ContainsAny(fmt.Sprint(v), "\n\r\x00") {
			return nil, fmt.Errorf("multiline Tetragon option %s is unsupported", k)
		}
		// These are managed to keep collectors local and events readable by this agent.
		switch k {
		case "export-filename", "server-address", "health-server-address", "metrics-server", "config-dir", "tracing-policy-dir", "export-file-compress", "enable-k8s-api", "export-file-max-size-mb", "export-file-max-backups":
			return nil, fmt.Errorf("Tetragon option %s is managed by the agent", k)
		}
		result[k] = fmt.Sprint(v)
	}
	return result, nil
}
