package audit

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"anqu/internal/security"
	"go.yaml.in/yaml/v3"
)

func TestNativeFIMDefaultsKeepMissingCronCandidates(t *testing.T) {
	c := Config{
		OutputDir: "/var/lib/anquan", StateFile: "/var/lib/anquan/state/md5.json", Server: []string{"127.0.0.1:55555"},
		Security: &SecurityConfig{Config: security.Config{Enabled: true}, NativeFIM: &NativeFIMConfig{Enabled: true}},
	}
	// Linux path normalization is independent of this test host and must not
	// stat/filter these paths: absent candidates need to remain observable.
	if err := normalizeSecurity(&c, "/srv/anquan", targetPathRules(false)); err != nil {
		t.Fatal(err)
	}
	for _, path := range security.DefaultCronPaths() {
		if !slices.Contains(c.Security.NativeFIM.Paths, path) {
			t.Fatalf("default FIM omitted optional cron candidate %s", path)
		}
	}
	if !slices.Contains(c.Security.NativeFIM.Paths, "/root/.ssh") {
		t.Fatal("cron defaults replaced an existing non-cron default")
	}
	c.Security.NativeFIM.Paths = []string{"/opt/explicit-monitor"}
	if err := normalizeSecurity(&c, "/srv/anquan", targetPathRules(false)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Security.NativeFIM.Paths, []string{"/opt/explicit-monitor"}) {
		t.Fatal("explicit FIM scope was silently expanded")
	}
}

func TestPublishedSecurityExampleIncludesAllCronCandidates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "security.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.Security == nil || c.Security.NativeFIM == nil {
		t.Fatal("published example has no security FIM configuration")
	}
	for _, path := range security.DefaultCronPaths() {
		if !slices.Contains(c.Security.Auditd.WatchPaths, path) || !slices.Contains(c.Security.NativeFIM.Paths, path) {
			t.Fatalf("published audit/FIM scopes disagree on cron candidate %s", path)
		}
	}
}
