package security

import (
	"context"
	"os"
	"strings"
	"testing"

	"anqu/internal/downloadrelay"
)

type aptDumpRunner struct {
	*fakeRunner
	dump string
}

func (r *aptDumpRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "apt-config" {
		return r.dump, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestAPTProxyConflictsFailClosed(t *testing.T) {
	for _, dump := range []string{
		"Acquire::http::Proxy::archive.ubuntu.com \"DIRECT\";\n",
		"Acquire::https::Proxy::archive.ubuntu.com \"http://other:1234\";\n",
		"Dir::Etc::sourcelist \"/tmp/unchecked.list\";\n",
		"Dir::Etc::sourceparts \"/tmp/unchecked.sources\";\n",
	} {
		m, r := testManager(t, Config{})
		m.Runner = &aptDumpRunner{r, dump}
		if _, err := m.aptProxyOptions(context.Background(), "http://127.0.0.1:1234"); err == nil {
			t.Errorf("accepted bypass config: %s", dump)
		}
	}
	m, r := testManager(t, Config{})
	m.Runner = &aptDumpRunner{r, "Dir \"/\";\nDir::Etc \"etc/apt\";\nDir::Etc::sourcelist \"sources.list\";\nDir::Etc::sourceparts \"sources.list.d\";\nAcquire::http::Proxy-Auto-Detect \"/bin/custom\";\n"}
	options, err := m.aptProxyOptions(context.Background(), "http://127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(options, " "), "Acquire::http::Proxy-Auto-Detect=") {
		t.Fatal("auto-detect command was not disabled")
	}
}

func TestPackageManagerRelayOptions(t *testing.T) {
	for _, pkg := range []string{"apt-get", "dnf", "yum"} {
		t.Run(pkg, func(t *testing.T) {
			m, r := testManager(t, Config{InstallMissing: true})
			r.missing["auditctl"] = true
			if pkg != "apt-get" {
				r.missing["apt-get"] = true
			}
			if pkg == "yum" {
				r.missing["dnf"] = true
			}
			state := downloadrelay.New()
			state.Update("127.0.0.1:1", "172.22.0.11", "secret")
			m.DownloadRelay = state
			defer func() {
				if m.downloadProxy != nil {
					m.downloadProxy.Close()
				}
			}()
			r.fail = func(name string, args []string) error {
				if name == pkg && strings.Contains(strings.Join(args, " "), "install") {
					r.missing["auditctl"] = false
				}
				return nil
			}
			if err := m.ensurePackage(context.Background(), "auditctl", "auditd", "audit"); err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(r.calls, "\n")
			if pkg == "apt-get" {
				for _, want := range []string{"apt-config dump", "Acquire::http::Proxy=http://127.0.0.1:", "Acquire::https::Proxy=http://127.0.0.1:", "Acquire::http::Proxy-Auto-Detect=", "--no-install-recommends auditd"} {
					if !strings.Contains(joined, want) {
						t.Errorf("missing %q in %s", want, joined)
					}
				}
			} else {
				for _, want := range []string{"--noplugins", "--setopt=proxy=http://127.0.0.1:", "--setopt=*.proxy=http://127.0.0.1:", "install -y audit"} {
					if !strings.Contains(joined, want) {
						t.Errorf("missing %q in %s", want, joined)
					}
				}
			}
		})
	}
}

func TestNoMasterRelayCredentialNeverInstallsDirect(t *testing.T) {
	m, r := testManager(t, Config{InstallMissing: true})
	r.missing["auditctl"] = true
	m.DownloadRelay = downloadrelay.New()
	m.DownloadRelay.Update("127.0.0.1:1", "172.22.0.11", "")
	if err := m.ensurePackage(context.Background(), "auditctl", "auditd", "audit"); err == nil {
		t.Fatal("missing relay credential accepted")
	}
	if len(r.calls) != 0 {
		t.Fatalf("package command executed: %v", r.calls)
	}
}

func TestAPTRejectsUnproxiedSourceMethods(t *testing.T) {
	m, _ := testManager(t, Config{})
	for _, source := range []string{"deb ftp://mirror.example/ubuntu noble main\n", "Types: deb\nURIs: mirror+http://mirror.example/list\nSuites: noble\n"} {
		path := "/etc/apt/sources.list"
		if strings.HasPrefix(source, "Types:") {
			path = "/etc/apt/sources.list.d/custom.sources"
		}
		put(t, m, path, []byte(source))
		if err := m.validateAPTSourceMethods(); err == nil {
			t.Fatalf("accepted bypass: %q", source)
		}
		os.Remove(m.path(path))
	}
	put(t, m, "/etc/apt/sources.list.d/ubuntu.sources", []byte("Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\n http://security.ubuntu.com/ubuntu\nSuites: noble\n"))
	if err := m.validateAPTSourceMethods(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCommandsRemoveInheritedBypassEnvironment(t *testing.T) {
	t.Setenv("no_proxy", "*")
	t.Setenv("NO_PROXY", "archive.ubuntu.com")
	t.Setenv("HTTP_PROXY", "http://untrusted:9999")
	t.Setenv("all_proxy", "socks://untrusted:1234")
	env := commandEnvironment(relayCommandContext(context.Background(), "http://127.0.0.1:34567"))
	values := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for _, key := range []string{"no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY"} {
		if values[key] != "" {
			t.Errorf("%s=%q", key, values[key])
		}
	}
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"} {
		if values[key] != "http://127.0.0.1:34567" {
			t.Errorf("%s=%q", key, values[key])
		}
	}
}

func TestDownloadThroughBrokenRelayDoesNotFetchOriginDirectly(t *testing.T) {
	_, err := secureDownloadVia(context.Background(), "https://example.invalid/a", 100, "http://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("expected proxy failure: %v", err)
	}
}
