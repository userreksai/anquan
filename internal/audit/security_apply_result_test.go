package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"anqu/internal/security"
)

func TestSuccessfulPolicyReconcileClearsPersistedInitializationError(t *testing.T) {
	c := Config{runtimeDir: t.TempDir()}
	failure := errors.New("temporary policy activation failure")
	statuses := []security.ComponentStatus{{Name: "policies", Enabled: true, State: "error", Message: failure.Error()}}
	if err := recordSecurityApplyResult(c, io.Discard, statuses, failure); !errors.Is(err, failure) {
		t.Fatalf("activation error lost: %v", err)
	}
	statePath := filepath.Join(securityDataDir(c), "apply-error.state")
	var saved map[string]any
	if err := readState(statePath, "security-apply-error", &saved); err != nil || saved["error"] != failure.Error() {
		t.Fatalf("initialization failure not persisted: %#v %v", saved, err)
	}
	if err := recordSecurityApplyResult(c, io.Discard, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("successful periodic repair left the old initialization error on the page")
	}
}
