package security

import (
	"context"
	"debug/buildinfo"
	"regexp"
	"runtime/debug"
	"strings"
)

var tetragonReportedVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)*$`)

func validTetragonVersion(value string) bool {
	return len(value) <= 200 && tetragonReportedVersion.MatchString(value)
}

func tetragonServerVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "Server version:"); ok {
			value = strings.TrimSpace(value)
			if validTetragonVersion(value) {
				return value
			}
		}
	}
	return ""
}

func tetragonBuildVersion(info *debug.BuildInfo) string {
	if info == nil || info.Main.Path != "github.com/cilium/tetragon" {
		return ""
	}
	// Official tarballs inject the daemon version with -X, even when the Go
	// module version is (devel). Read the installed binary, never the desired
	// installation version or the potentially different tetra CLI version.
	const versionAssignment = "github.com/cilium/tetragon/pkg/version.Version="
	for _, setting := range info.Settings {
		if setting.Key != "-ldflags" {
			continue
		}
		fields := strings.Fields(setting.Value)
		for i := 0; i < len(fields); i++ {
			field := strings.Trim(fields[i], "'\"")
			var assignment string
			if field == "-X" && i+1 < len(fields) {
				i++
				assignment = strings.Trim(fields[i], "'\"")
			} else if value, ok := strings.CutPrefix(field, "-X="); ok {
				assignment = strings.Trim(value, "'\"")
			}
			if value, ok := strings.CutPrefix(assignment, versionAssignment); ok && validTetragonVersion(value) {
				return value
			}
		}
	}
	if validTetragonVersion(info.Main.Version) {
		return info.Main.Version
	}
	return ""
}

func (m *Manager) tetragonVersion(ctx context.Context, binaryPath string) string {
	if ctx.Err() != nil {
		return ""
	}
	if _, err := m.Runner.LookPath("tetra"); err == nil {
		out, err := m.Runner.Run(ctx, "tetra", "--server-address", "unix:///var/run/tetragon/tetragon.sock", "--timeout", "2s", "--retries", "0", "version", "--server")
		if err == nil {
			if version := tetragonServerVersion(out); version != "" {
				return version
			}
		}
	}
	if ctx.Err() != nil {
		return ""
	}
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return ""
	}
	return tetragonBuildVersion(info)
}
