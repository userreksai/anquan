package audit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConfigACKErrorKeepsFinalUTF8ErrorWithinMasterLimit(t *testing.T) {
	value := strings.Repeat("下载中", 1800) + "\nE: connection timed out 软件源不可达"
	got := boundedConfigACKError(value)
	if len(got) > 4096 || !utf8.ValidString(got) {
		t.Fatalf("invalid bounded ACK length=%d", len(got))
	}
	if !strings.HasSuffix(got, "E: connection timed out 软件源不可达") || !strings.Contains(got, "security_apply_failed") {
		t.Fatalf("lost actionable error: %s", got)
	}
	if boundedConfigACKError("ordinary failure") != "ordinary failure" {
		t.Fatal("short error changed")
	}
}
