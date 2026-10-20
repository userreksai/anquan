package security

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type downloadEnvironmentKey struct{}

func relayCommandContext(ctx context.Context, proxy string) context.Context {
	if proxy == "" {
		return ctx
	}
	return context.WithValue(ctx, downloadEnvironmentKey{}, proxy)
}

func commandEnvironment(ctx context.Context) []string {
	proxy, _ := ctx.Value(downloadEnvironmentKey{}).(string)
	env := os.Environ()
	if proxy != "" {
		clean := make([]string, 0, len(env)+8)
		for _, entry := range env {
			name, _, _ := strings.Cut(entry, "=")
			switch strings.ToLower(name) {
			case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
				continue
			}
			clean = append(clean, entry)
		}
		env = append(clean, "http_proxy="+proxy, "HTTP_PROXY="+proxy, "https_proxy="+proxy, "HTTPS_PROXY="+proxy, "all_proxy=", "ALL_PROXY=", "no_proxy=", "NO_PROXY=")
	}
	return append(env, "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
}

func (m *Manager) packageProxy(ctx context.Context) (string, error) {
	if m.DownloadRelay == nil {
		return "", nil
	} // Standalone installations retain their local package source behavior.
	if m.downloadProxy == nil {
		p, err := m.DownloadRelay.Start(ctx)
		if err != nil {
			return "", err
		}
		m.downloadProxy = p
	}
	return m.downloadProxy.URL(), nil
}

// Host-specific APT proxies take precedence over the global command-line proxy.
// Refuse them rather than silently let a DIRECT rule bypass the master.
func (m *Manager) aptProxyOptions(ctx context.Context, proxy string) ([]string, error) {
	if proxy == "" {
		return nil, nil
	}
	if _, err := m.Runner.LookPath("apt-config"); err != nil {
		return nil, errors.New("apt-config is required to verify package relay proxy settings")
	}
	dump, err := m.Runner.Run(ctx, "apt-config", "dump")
	if err != nil {
		return nil, fmt.Errorf("inspect APT proxy settings: %w", err)
	}
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if strings.HasPrefix(key, "acquire::http::proxy::") || strings.HasPrefix(key, "acquire::https::proxy::") {
			return nil, fmt.Errorf("APT host-specific proxy setting %s could bypass the master; remove it before automatic installation", fields[0])
		}
		// Source validation below reads the standard source locations. A custom
		// APT directory must not silently supply an unchecked ftp/mirror method.
		if len(fields) > 1 && (key == "dir" || key == "dir::etc" || key == "dir::etc::sourcelist" || key == "dir::etc::sourceparts") {
			raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))
			value, parseErr := strconv.Unquote(strings.TrimSuffix(raw, ";"))
			if parseErr != nil {
				return nil, fmt.Errorf("cannot validate effective APT setting %s", fields[0])
			}
			allowed := true
			switch key {
			case "dir":
				allowed = value == "/" || value == ""
			case "dir::etc":
				allowed = value == "etc/apt" || value == "etc/apt/" || value == "/etc/apt" || value == "/etc/apt/"
			case "dir::etc::sourcelist":
				allowed = value == "sources.list" || value == "/etc/apt/sources.list"
			case "dir::etc::sourceparts":
				allowed = value == "sources.list.d" || value == "sources.list.d/" || value == "/etc/apt/sources.list.d" || value == "/etc/apt/sources.list.d/"
			}
			if !allowed {
				return nil, fmt.Errorf("APT custom source directory %s cannot be safely checked for package relay installation", fields[0])
			}
		}
	}
	if err := m.validateAPTSourceMethods(); err != nil {
		return nil, err
	}
	return []string{"-o", "Acquire::http::Proxy=" + proxy, "-o", "Acquire::https::Proxy=" + proxy,
		"-o", "Acquire::http::Proxy-Auto-Detect=", "-o", "Acquire::https::Proxy-Auto-Detect=",
		"-o", "Acquire::http::ProxyAutoDetect=", "-o", "Acquire::https::ProxyAutoDetect=",
		"-o", "Acquire::Retries=0"}, nil
}

func packageSourceURI(value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file" && u.Scheme != "cdrom") {
		return fmt.Errorf("APT source %q uses a method that cannot be confined to the master HTTP relay", value)
	}
	return nil
}

func (m *Manager) validateAPTSourceMethods() error {
	paths := []string{m.path("/etc/apt/sources.list")}
	entries, err := os.ReadDir(m.path("/etc/apt/sources.list.d"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".list") || strings.HasSuffix(entry.Name(), ".sources")) {
			paths = append(paths, filepath.Join(m.path("/etc/apt/sources.list.d"), entry.Name()))
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".sources") {
			for _, paragraph := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
				disabled := false
				uriLines := []string{}
				readingURI := false
				for _, line := range strings.Split(paragraph, "\n") {
					trim := strings.TrimSpace(line)
					if strings.HasPrefix(trim, "#") {
						continue
					}
					if strings.HasPrefix(strings.ToLower(trim), "enabled:") && strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(trim), "enabled:")), "no") {
						disabled = true
					}
					if strings.HasPrefix(strings.ToLower(line), "uris:") {
						uriLines = append(uriLines, line[len("URIs:"):])
						readingURI = true
						continue
					}
					if readingURI && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
						uriLines = append(uriLines, trim)
					} else {
						readingURI = false
					}
				}
				if !disabled {
					for _, line := range uriLines {
						for _, uri := range strings.Fields(line) {
							if err := packageSourceURI(uri); err != nil {
								return err
							}
						}
					}
				}
			}
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) == 0 || (fields[0] != "deb" && fields[0] != "deb-src") {
					continue
				}
				fields = fields[1:]
				if len(fields) > 0 && strings.HasPrefix(fields[0], "[") {
					for len(fields) > 0 {
						end := strings.HasSuffix(fields[0], "]")
						fields = fields[1:]
						if end {
							break
						}
					}
				}
				if len(fields) > 0 {
					if err := packageSourceURI(fields[0]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
