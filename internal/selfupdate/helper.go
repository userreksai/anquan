package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type helperOperations struct {
	stop         func(context.Context) error
	start        func(context.Context) error
	readyTimeout time.Duration
	poll         time.Duration
}

// RunHelper is called before installation preparation. The helper is a private
// copy of the previously running Agent, outside agent.service's process group.
func RunHelper(path string) error {
	if !helperEligible(path) {
		return errors.New("update helper requires the root-owned installed update journal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return runHelper(ctx, stateDirectory, InstalledExecutable, helperOperations{
		stop:         func(ctx context.Context) error { return serviceCommand(ctx, "stop") },
		start:        func(ctx context.Context) error { return serviceCommand(ctx, "start") },
		readyTimeout: 60 * time.Second, poll: 250 * time.Millisecond,
	})
}

func runHelper(ctx context.Context, directory, executable string, ops helperOperations) error {
	state, err := readJournal(directory)
	if err != nil {
		return err
	}
	if state.Status != "queued" {
		return errors.New("update journal is not queued")
	}
	stage, backup := filepath.Join(directory, "candidate"), filepath.Join(directory, "backup")
	if digest, err := hashFile(stage); err != nil || digest != state.BinarySHA256 {
		state.Status = "failed"
		state.Error = "staged Agent digest changed"
		_ = writeJournal(directory, state)
		return errors.New(state.Error)
	}
	if digest, err := hashFile(backup); err != nil || digest != state.PreviousSHA256 {
		state.Status = "failed"
		state.Error = "Agent backup digest changed"
		_ = writeJournal(directory, state)
		return errors.New(state.Error)
	}
	if err := atomicFile(filepath.Join(directory, "helper-started"), []byte(state.JobID), 0600); err != nil {
		return err
	}
	if err := ops.stop(ctx); err != nil {
		// Stop may have partially succeeded. Always restore service availability.
		state.Status = "failed"
		state.Error = "cannot stop Agent service: " + boundedError(err)
		_ = writeJournal(directory, state)
		_ = ops.start(ctx)
		return errors.New(state.Error)
	}
	rollback := func(cause error) error {
		// Use an independent bounded context: the original start/wait may have
		// timed out, but rollback must still be able to stop and restart.
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		stopErr := ops.stop(recoveryCtx)
		restoreErr := copyExecutable(backup, executable)
		if restoreErr == nil {
			restoreErr = os.Chmod(executable, 0755)
		}
		state.Status = "rolled_back"
		state.Error = boundedError(cause)
		if restoreErr != nil {
			state.Status = "failed"
		}
		// Persist before starting the preserved Agent, so its first hello
		// already carries the rollback outcome.
		_ = writeJournal(directory, state)
		startErr := ops.start(recoveryCtx)
		if stopErr != nil || restoreErr != nil || startErr != nil {
			state.Status = "failed"
			state.Error = fmt.Sprintf("%s; rollback stop=%v restore=%v start=%v", state.Error, stopErr, restoreErr, startErr)
		}
		_ = writeJournal(directory, state)
		return errors.New(state.Error)
	}
	state.Status = "restarting"
	if err := writeJournal(directory, state); err != nil {
		return rollback(err)
	}
	// The installed binary also serves existing non-root SSH login hooks.
	// Staging remains private, while its final executable keeps install's mode.
	if err := os.Chmod(stage, 0755); err != nil {
		return rollback(err)
	}
	if err := os.Rename(stage, executable); err != nil {
		return rollback(fmt.Errorf("replace Agent binary: %w", err))
	}
	if err := syncDirectory(filepath.Dir(executable)); err != nil {
		return rollback(err)
	}
	if err := ops.start(ctx); err != nil {
		return rollback(fmt.Errorf("start new Agent: %w", err))
	}
	waitCtx, cancel := context.WithTimeout(ctx, ops.readyTimeout)
	defer cancel()
	ticker := time.NewTicker(ops.poll)
	defer ticker.Stop()
	for {
		ready, err := readJournal(directory)
		if err == nil && ready.JobID == state.JobID && ready.Status == "applied" {
			if digest, err := hashFile(executable); err == nil && digest == state.BinarySHA256 {
				return nil
			}
			return rollback(errors.New("running Agent digest changed before readiness"))
		}
		select {
		case <-waitCtx.Done():
			return rollback(errors.New("new Agent did not confirm readiness within the update deadline"))
		case <-ticker.C:
		}
	}
}
