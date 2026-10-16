package security

import (
	"context"
	"errors"
	"testing"
)

func TestRunReportsStatusEnqueueFailure(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true})
	want := errors.New("outbox full")
	err := m.Run(context.Background(), func(Event) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("status enqueue failure hidden: %v", err)
	}
}
