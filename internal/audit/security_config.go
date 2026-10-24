package audit

import (
	"fmt"
	"strings"

	"anqu/internal/security"
)

// SecurityConfig extends the component controller with this Agent's native FIM.
// It travels inside the existing encrypted YAML assignment, without new ports.
type SecurityConfig struct {
	security.Config `yaml:",inline"`
	NativeFIM       *NativeFIMConfig       `json:"native_fim,omitempty" yaml:"native_fim,omitempty"`
	SSHAuth         *SecuritySSHAuthConfig `json:"ssh_auth,omitempty" yaml:"ssh_auth,omitempty"`
}

type SecuritySSHAuthConfig struct {
	Enabled                bool `json:"enabled" yaml:"enabled"`
	PollIntervalSeconds    int  `json:"poll_interval_seconds" yaml:"poll_interval_seconds"`
	InitialLookbackSeconds int  `json:"initial_lookback_seconds" yaml:"initial_lookback_seconds"`
	AlertThreshold         int  `json:"alert_threshold" yaml:"alert_threshold"`
	WindowSeconds          int  `json:"window_seconds" yaml:"window_seconds"`
}

type NativeFIMConfig struct {
	Enabled               bool     `json:"enabled" yaml:"enabled"`
	Paths                 []string `json:"paths" yaml:"paths"`
	PollIntervalSeconds   int      `json:"poll_interval_seconds" yaml:"poll_interval_seconds"`
	ReportChanges         bool     `json:"report_changes" yaml:"report_changes"`
	CaptureCreatedContent *bool    `json:"capture_created_content,omitempty" yaml:"capture_created_content,omitempty"`
	MaxDiffBytes          int      `json:"max_diff_bytes" yaml:"max_diff_bytes"`
}

func normalizeSecurity(c *Config, base string, rules pathRules) error {
	if c.Security == nil {
		return nil
	}
	c.Security.Normalize()
	if err := c.Security.Validate(); err != nil {
		return fmt.Errorf("security: %w", err)
	}
	if !c.Security.Enabled {
		return nil
	}
	if len(c.Server) == 0 {
		return fmt.Errorf("security.enabled requires at least one server for acknowledged reporting")
	}
	if s := c.Security.SSHAuth; s != nil && s.Enabled {
		if s.PollIntervalSeconds == 0 {
			s.PollIntervalSeconds = 5
		}
		if s.InitialLookbackSeconds == 0 {
			s.InitialLookbackSeconds = 300
		}
		if s.AlertThreshold == 0 {
			s.AlertThreshold = 5
		}
		if s.WindowSeconds == 0 {
			s.WindowSeconds = 300
		}
		if s.PollIntervalSeconds < 1 || s.PollIntervalSeconds > 300 || s.InitialLookbackSeconds < 1 || s.InitialLookbackSeconds > 86400 || s.AlertThreshold < 1 || s.AlertThreshold > 1000 || s.WindowSeconds < 10 || s.WindowSeconds > 86400 {
			return fmt.Errorf("invalid security.ssh_auth polling/lookback/threshold/window")
		}
	}
	f := c.Security.NativeFIM
	if f == nil || !f.Enabled {
		return nil
	}
	if f.CaptureCreatedContent == nil {
		enabled := true
		f.CaptureCreatedContent = &enabled
	}
	if f.PollIntervalSeconds == 0 {
		f.PollIntervalSeconds = 30
	}
	if f.MaxDiffBytes == 0 {
		f.MaxDiffBytes = 8192
	}
	if f.PollIntervalSeconds < 1 || f.PollIntervalSeconds > 86400 {
		return fmt.Errorf("security.native_fim.poll_interval_seconds must be 1..86400")
	}
	if f.MaxDiffBytes < 256 || f.MaxDiffBytes > 16384 {
		return fmt.Errorf("security.native_fim.max_diff_bytes must be 256..16384")
	}
	if len(f.Paths) == 0 {
		f.Paths = append([]string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/root/.ssh"}, security.DefaultCronPaths()...)
	}
	if len(f.Paths) > 256 {
		return fmt.Errorf("security.native_fim.paths exceeds 256 roots")
	}
	seen := map[string]bool{}
	for i, p := range f.Paths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("security.native_fim.paths cannot contain empty paths")
		}
		resolved, err := rules.resolve(base, p)
		if err != nil {
			return err
		}
		if rules.inside(c.OutputDir, resolved) || rules.key(resolved) == rules.key(c.StateFile) {
			return fmt.Errorf("native FIM root cannot monitor Agent output/state")
		}
		if seen[rules.key(resolved)] {
			return fmt.Errorf("duplicate native FIM root %s", resolved)
		}
		seen[rules.key(resolved)] = true
		f.Paths[i] = resolved
	}
	return nil
}
