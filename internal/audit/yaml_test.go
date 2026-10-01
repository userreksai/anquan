package audit

import (
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const inlineYAML = `# 中文注释：单文件巡检配置
output_dir: output
state_file: state/md5.json
timezone: Asia/Shanghai
md5:
  paths: [watched]
  exclude_paths: []
login:
  source: jsonl
  path: login.jsonl
existence:
  base_dir: watched
  files:
    - path: app.conf
      type: file
`

func TestYAMLStandaloneLifecycle(t *testing.T) {
	for _, extension := range []string{".yaml", ".yml", ".YAML"} {
		t.Run(extension, func(t *testing.T) {
			legacy := testConfig(t)
			root := filepath.Dir(legacy.OutputDir)
			// Invalid legacy files next to YAML must not be consulted.
			for _, name := range []string{"config.json", "files.json"} {
				put(t, filepath.Join(root, name), "invalid legacy input")
			}
			path := filepath.Join(root, "config"+extension)
			put(t, path, "\xef\xbb\xbf"+inlineYAML)
			c, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if !c.MD5.Enabled || !c.MD5.Recursive || !c.Login.Enabled || !c.Existence.Enabled || c.Login.TimeoutSeconds != 10 || c.Login.MaxRecords != 1000 {
				t.Fatal("YAML defaults lost")
			}
			if c.Existence.Files[0].Path != "app.conf" {
				t.Fatal("inline list was mutated or a separate list is required")
			}
			if c.OutputDir != legacy.OutputDir || c.StateFile != legacy.StateFile || c.Login.Path != legacy.Login.Path {
				t.Fatal("relative YAML paths resolved incorrectly")
			}
			r, _ := runOK(t, c)
			if !r.MD5.BaselineCreated || r.Existence.Missing != 0 || len(r.Existence.Items) != 1 || r.Login.Record == nil {
				t.Fatalf("bad first YAML run: %+v", r)
			}
			put(t, filepath.Join(root, "watched", "app.conf"), "changed via YAML\n")
			r, _ = runOK(t, c)
			if len(r.MD5.Changes) != 1 || r.MD5.Changes[0].Kind != "modified" {
				t.Fatal("YAML scan did not detect modification")
			}
			// Editing the one YAML file changes the checks on the next load.
			put(t, path, strings.Replace(inlineYAML, "path: app.conf", "path: missing.conf", 1))
			c, err = LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			r, _ = runOK(t, c)
			if r.Existence.Missing != 1 || len(r.MD5.Changes) != 0 {
				t.Fatal("edited inline checks were not loaded")
			}
		})
	}
}

func TestEmbeddedParsingPreservesBaseline(t *testing.T) {
	c := testConfig(t)
	runOK(t, c)
	originalScope := scopeID(c)
	entries, err := loadChecks(c.Existence)
	if err != nil {
		t.Fatal(err)
	}
	c.Existence.Files = entries
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c, err = ParseConfig(b, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if scopeID(c) != originalScope {
		t.Fatal("format migration changed MD5 scope")
	}
	put(t, filepath.Join(c.MD5.Paths[0], "app.conf"), "modified before migration scan")
	r, _ := runOK(t, c)
	if r.MD5.BaselineCreated || len(r.MD5.Changes) != 1 || r.MD5.Cumulative["modified"] != 1 {
		t.Fatal("migration reset the baseline or lost changes")
	}
}

func TestYAMLRejectsInvalidConfig(t *testing.T) {
	cases := map[string]string{
		"unknown-field":                inlineYAML + "typo: true\n",
		"unknown-nested-field":         strings.Replace(inlineYAML, "  paths:", "  typo: true\n  paths:", 1),
		"duplicate-key":                inlineYAML + "output_dir: other\n",
		"invalid-type":                 strings.Replace(inlineYAML, "  paths: [watched]", "  paths: [watched]\n  recursive: invalid", 1),
		"multiple-documents":           inlineYAML + "---\noutput_dir: other\n",
		"empty-files":                  strings.Replace(inlineYAML, "  files:\n    - path: app.conf\n      type: file", "  files: []", 1),
		"missing-files":                strings.Replace(inlineYAML, "  files:\n    - path: app.conf\n      type: file", "", 1),
		"conflicting-lists":            strings.Replace(inlineYAML, "  files:", "  list_file: files.json\n  files:", 1),
		"empty-files-with-legacy-list": strings.Replace(inlineYAML, "  files:\n    - path: app.conf\n      type: file", "  list_file: files.json\n  files: []", 1),
		"duplicate-path":               inlineYAML + "    - path: app.conf\n      type: file\n",
		"relative-escape":              strings.Replace(inlineYAML, "path: app.conf", "path: ../escape", 1),
		"unknown-entry-field":          inlineYAML + "      typo: true\n",
		"invalid-entry-type":           strings.Replace(inlineYAML, "type: file", "type: bad", 1),
		"tab-indentation":              strings.Replace(inlineYAML, "  paths:", "\tpaths:", 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			path := filepath.Join(filepath.Dir(c.OutputDir), "config.yaml")
			put(t, path, content)
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("invalid YAML configuration accepted")
			}
		})
	}
}

func TestYAMLInlineCheckPathsAndTypes(t *testing.T) {
	c := testConfig(t)
	root := filepath.Dir(c.OutputDir)
	put(t, filepath.Join(root, "watched", "配置 #1.conf"), "中文")
	content := strings.Replace(inlineYAML, "    - path: app.conf\n      type: file", `    - path: "配置 #1.conf" # 行内中文注释
    - path: .
      type: directory
    - path: app.conf
      type: any`, 1)
	path := filepath.Join(root, "config.yaml")
	put(t, path, content)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := runOK(t, c)
	if len(r.Existence.Items) != 3 || r.Existence.Missing != 0 || r.Existence.TypeMismatch != 0 {
		t.Fatalf("bad inline checks: %+v", r.Existence)
	}
	if c.Existence.Files[0].Type != "" {
		t.Fatal("validation mutated default type in input")
	}
}

func TestYAMLDisabledChecksNeedNoList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	put(t, path, "output_dir: output\nmd5:\n  enabled: false\nlogin:\n  enabled: false\nexistence:\n  enabled: false\n")
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	runOK(t, c)
}

func TestJSONConfigurationRemoved(t *testing.T) {
	jsonConfig := `{"output_dir":"output","md5":{"enabled":false},"login":{"enabled":false},"existence":{"enabled":false}}`
	for _, ext := range []string{".json", ".yaml", ".yml"} {
		path := filepath.Join(t.TempDir(), "config"+ext)
		put(t, path, jsonConfig)
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted JSON configuration as %s", ext)
		}
	}
	if _, err := ParseConfig([]byte(jsonConfig), t.TempDir()); err == nil {
		t.Fatal("accepted embedded JSON configuration")
	}
	if err := ValidateEmbeddedYAML([]byte(jsonConfig), "linux"); err == nil {
		t.Fatal("builder accepted JSON configuration")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	put(t, path, inlineYAML)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted obsolete .json configuration filename")
	}
}

func TestEmbeddedRelativePathsUseDeploymentDirectory(t *testing.T) {
	data := []byte(strings.Replace(inlineYAML, "  path: login.jsonl", "  path: login.jsonl\n  last_command: tools/last", 1))
	for _, dir := range []string{filepath.Join(t.TempDir(), "B"), filepath.Join(t.TempDir(), "C")} {
		c, err := ParseConfig(data, dir)
		if err != nil {
			t.Fatal(err)
		}
		if c.OutputDir != filepath.Join(dir, "output") || c.StateFile != filepath.Join(dir, "output", "state", "md5.json") || c.MD5.Paths[0] != filepath.Join(dir, "watched") || c.Login.Path != filepath.Join(dir, "login.jsonl") || c.Login.LastCommand != filepath.Join(dir, "tools", "last") {
			t.Fatalf("incorrect node-relative resolution: %+v", c)
		}
		checks, err := loadChecks(c.Existence)
		if err != nil || checks[0].Path != filepath.Join(dir, "watched", "app.conf") {
			t.Fatalf("checks not relative to deployment directory: %+v, %v", checks, err)
		}
	}
}

func TestBuildValidationUsesTargetOSWithoutFilesystem(t *testing.T) {
	linux := "output_dir: /usr/local/anqu\nmd5:\n  paths: [/nonexistent-target-node/etc/app.conf]\nlogin:\n  path: /nonexistent-target-node/var/log/wtmp\nexistence:\n  base_dir: /nonexistent-target-node/etc\n  files:\n    - path: app.conf\n"
	windows := "output_dir: C:/anqu/output\nmd5:\n  paths: [C:/nonexistent-target-node/app.conf]\nlogin:\n  enabled: false\nexistence:\n  base_dir: C:/nonexistent-target-node\n  files:\n    - path: app.conf\n"
	for _, tc := range []struct {
		name, os, data string
		valid          bool
	}{
		{"Linux paths on any build host", "linux", linux, true},
		{"Windows paths on any build host", "windows", windows, true},
		{"runtime-relative paths", "linux", inlineYAML, true},
		{"Windows rooted path rejected", "windows", linux, false},
		{"unknown target OS", "invalid", linux, false},
		{"excluded MD5 root", "linux", strings.Replace(linux, "/nonexistent-target-node/etc/app.conf", "/usr/local/anqu/config.yaml", 1), false},
		{"relative check escapes", "linux", strings.Replace(linux, "path: app.conf", "path: ../escape", 1), false},
		{"Windows duplicate case-insensitive path", "windows", windows + "    - path: APP.CONF\n", false},
		{"Linux distinct case-sensitive paths", "linux", linux + "    - path: APP.CONF\n", true},
		{"Windows drive-relative path rejected", "windows", strings.Replace(windows, "C:/anqu/output", "C:output", 1), false},
		{"removed list_file", "linux", linux + "  list_file: files.json\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEmbeddedYAML([]byte(tc.data), tc.os)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t got err=%v", tc.valid, err)
			}
		})
	}
}
