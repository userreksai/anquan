package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anqu/internal/security"
)

func pollTaskResults(c Config, emit func(security.Event) error) error {
	dir := filepath.Join(securityDataDir(c), "task-spool")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	processed := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".age") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 {
			return fmt.Errorf("invalid task result spool entry")
		}
		path := filepath.Join(dir, entry.Name())
		var event security.Event
		if err := readState(path, "security-task", &event); err != nil {
			return err
		}
		if event.Type != "security_event" || event.ID == "" || event.Data["source"] != "task" {
			return fmt.Errorf("invalid task event identity/source")
		}
		if err := emit(event); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		processed++
		if processed >= 64 {
			break
		}
	}
	return nil
}

func taskResultsLoop(ctx context.Context, c Config, emit func(security.Event) error, health func(error)) {
	for ctx.Err() == nil {
		health(pollTaskResults(c, emit))
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
