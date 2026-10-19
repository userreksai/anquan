package security

import "testing"

func TestLogRotationCandidates(t *testing.T) {
	cases := []struct {
		base, name string
		want       bool
	}{
		{"tetragon.log", "tetragon.log", true},
		{"tetragon.log", "tetragon.log.1", true},
		{"audit.log", "audit.log.2", true},
		{"anquan-sudo.log", "anquan-sudo.log.1", true},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.755.log", true},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.000.log", true},
		{"events", "events-2026-10-18T22-27-08.755", true},
		{"events.json.log", "events.json-2026-10-18T22-27-08.755.log", true},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.755.log.gz", false},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.755.log.tmp", false},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.755.json", false},
		{"tetragon.log", "other-2026-10-18T22-27-08.755.log", false},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08.log", false},
		{"tetragon.log", "tetragon-2026-10-18T22-27-08,755.log", false},
		{"tetragon.log", "tetragon-2026-13-18T22-27-08.755.log", false},
		{"tetragon.log", "tetragon-unrelated.log", false},
		{"tetragon.log", "tetragon-.log", false},
	}
	for _, tc := range cases {
		t.Run(tc.base+"/"+tc.name, func(t *testing.T) {
			if got := isLogRotationCandidate(tc.base, tc.name); got != tc.want {
				t.Fatalf("isLogRotationCandidate(%q, %q) = %v, want %v", tc.base, tc.name, got, tc.want)
			}
		})
	}
}
