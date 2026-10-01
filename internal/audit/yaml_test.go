package audit

import (
	"os"
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
			// Prove that neither of the old configuration files is consulted.
			for _, name := range []string{"config.json", "files.json"} {
				if err := os.Remove(filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
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
			if c.Existence.ListFile != "" || c.Existence.Files[0].Path != "app.conf" {
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

func TestJSONToYAMLPreservesBaseline(t *testing.T) {
	c := testConfig(t)
	runOK(t, c)
	originalScope := scopeID(c)
	entries, err := loadChecks(c.Existence)
	if err != nil {
		t.Fatal(err)
	}
	c.Existence.ListFile = ""
	c.Existence.Files = entries
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(c.OutputDir), "config.yaml")
	put(t, path, string(b))
	c, err = LoadConfig(path)
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
