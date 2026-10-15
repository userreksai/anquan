package audit

import "testing"

func TestSSHExecutionModeDefaultsAndValidation(t *testing.T) {
	base := "output_dir: output\nmd5: {enabled: false}\nexistence: {enabled: false}\nlogin:\n  source: jsonl\n  path: login.jsonl\n"
	for _, mode := range []string{"", "trigger", "poll", "unknown"} {
		yaml := base
		if mode != "" {
			yaml += "  mode: " + mode + "\n"
		}
		c, err := ParseConfig([]byte(yaml), t.TempDir())
		if mode == "unknown" {
			if err == nil {
				t.Fatal("invalid SSH mode accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := mode
		if want == "" {
			want = "trigger"
		}
		if c.Login.Mode != want || c.runtimeDir == "" {
			t.Fatalf("mode/runtime directory not normalized: %q %q", c.Login.Mode, c.runtimeDir)
		}
	}
}
