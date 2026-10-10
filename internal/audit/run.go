package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func Run(c Config) (Report, OutputPaths, error) {
	return RunWithWriter(c, nil)
}

func RunWithWriter(c Config, writer io.Writer) (r Report, paths OutputPaths, runErr error) {
	return runWithWriter(c, writer, true)
}

func runWithWriter(c Config, writer io.Writer, startupHeartbeat bool) (r Report, paths OutputPaths, runErr error) {
	r = Report{Version: 2, Success: true, Errors: []Issue{}, Alerts: []Alert{}}
	if c.location == nil {
		return r, paths, fmt.Errorf("configuration must be loaded with LoadConfig")
	}
	defer func() {
		if runErr != nil {
			runErr = logRunFailure(c, writer, runErr)
		}
	}()
	if err := os.MkdirAll(c.OutputDir, 0755); err != nil {
		return r, paths, err
	}
	if err := os.MkdirAll(filepath.Dir(c.StateFile), 0700); err != nil {
		return r, paths, err
	}
	unlock, err := lockState(c.StateFile + ".lock")
	if err != nil {
		return r, paths, err
	}
	defer unlock()
	if err := prepareSession(c); err != nil {
		return r, paths, err
	}
	r.StartedAt = time.Now().In(c.location)
	paths.Log = logPath(c, r.StartedAt)
	if err := writeLog(c, writer, r.StartedAt, "scan_started", map[string]string{"state_file": c.StateFile}); err != nil {
		return r, paths, err
	}
	r.Host, err = os.Hostname()
	if err != nil {
		r.Errors = append(r.Errors, Issue{"host", err.Error()})
	}
	if startupHeartbeat {
		heartbeatOnce(c, writer, "")
	}
	var issues []Issue
	var next *baseline
	r.MD5, next, issues = collectMD5(c, r.StartedAt)
	r.Errors = append(r.Errors, issues...)
	var loginNext *loginBaseline
	if c.MonitoringMode() || c.Login.Source == "journal" || c.Login.Source == "authlog" {
		r.Login, loginNext, issues = collectSSHLogins(c, r.StartedAt)
	} else {
		r.Login, issues = collectLogin(c.Login, c.location)
	}
	r.Errors = append(r.Errors, issues...)
	r.Existence, issues = collectExistence(c.Existence)
	r.Errors = append(r.Errors, issues...)
	var filesNext *filesBaseline
	r.Files, filesNext, issues = collectFilesMonitoring(c, r.StartedAt)
	r.Errors = append(r.Errors, issues...)
	var processNext *processBaseline
	r.Processes, processNext, issues = collectProcessMonitoring(c, r.StartedAt)
	r.Errors = append(r.Errors, issues...)
	r.Alerts = append(r.Alerts, r.Files.Alerts...)
	r.Alerts = append(r.Alerts, r.Processes.Alerts...)
	for _, change := range r.MD5.Changes {
		r.Alerts = append(r.Alerts, Alert{Module: "md5", Kind: change.Kind, Target: change.Path, Before: change.Before, After: change.After, Message: "file content or membership changed"})
	}
	for _, item := range r.Existence.Items {
		if !item.Matches {
			r.Alerts = append(r.Alerts, Alert{Module: "existence", Kind: "missing_or_type_mismatch", Target: item.Path, Message: "configured file does not exist or has the wrong type"})
		}
	}
	for _, issue := range r.Errors {
		r.Alerts = append(r.Alerts, Alert{Module: issue.Module, Kind: "collection_error", Message: issue.Message})
	}
	r.FinishedAt = time.Now().In(c.location)
	r.Success = len(r.Errors) == 0
	r.Notifications = notifyServers(c, r)
	for _, notification := range r.Notifications {
		if notification.Error != "" {
			r.Errors = append(r.Errors, Issue{"udp", notification.Server + ": " + notification.Error})
			r.Success = false
		}
	}
	stamp := r.StartedAt.Format("20060102_150405.000000000-0700")
	paths = OutputPaths{
		JSON:   filepath.Join(c.OutputDir, stamp+".json"),
		Prom:   filepath.Join(c.OutputDir, stamp+".prom"),
		Latest: filepath.Join(c.OutputDir, "textfile", "anqu.prom"),
		Log:    logPath(c, r.StartedAt),
	}
	if c.Setup != nil {
		paths.Prom = c.Setup.Prom
	}
	if err := publish(r, paths, c.MonitoringMode()); err != nil {
		return r, paths, err
	}
	if err := writeReportLog(c, writer, r); err != nil {
		return r, paths, err
	}
	// Commit only after the reports have been published. A crash before this point
	// may repeat a change next time, but cannot silently consume an unreported change.
	type commit struct {
		module, path string
		data         any
		failed       func()
	}
	var commits []commit
	if next != nil {
		commits = append(commits, commit{"md5", c.StateFile, next, func() { r.MD5.Success, r.MD5.BaselineCreated = false, false }})
	}
	if filesNext != nil {
		commits = append(commits, commit{"files", c.StateFile + ".files", filesNext, func() { r.Files.Success, r.Files.BaselineCreated = false, false }})
	}
	if processNext != nil {
		commits = append(commits, commit{"processes", c.StateFile + ".processes", processNext, func() { r.Processes.Success, r.Processes.BaselineCreated = false, false }})
	}
	if loginNext != nil {
		commits = append(commits, commit{"login", c.StateFile + ".logins", loginNext, func() { r.Login.Success = false }})
	}
	stateFailure := false
	for _, item := range commits {
		if err := writeState(item.path, item.module, item.data); err != nil {
			stateFailure, r.Success = true, false
			item.failed()
			r.Errors = append(r.Errors, Issue{item.module, "save baseline: " + err.Error()})
		} else if c.session != nil {
			c.session.committed[item.module] = true
		}
	}
	if stateFailure {
		if err := publish(r, paths, c.MonitoringMode()); err != nil {
			return r, paths, err
		}
		if err := writeLog(c, writer, time.Now(), "state_commit_failed", r.Errors); err != nil {
			return r, paths, err
		}
	}
	if err := writeScanComplete(c, writer, r); err != nil {
		return r, paths, err
	}
	return r, paths, nil
}

func publish(r Report, paths OutputPaths, historical ...bool) error {
	if err := writeJSON(paths.JSON, r, 0640); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	b := metrics(r)
	archive := b
	if len(historical) > 0 && historical[0] {
		archive = snapshotMetrics(r, b)
	}
	if err := atomicWrite(paths.Prom, archive, 0644); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}
	if err := atomicWrite(paths.Latest, b, 0644); err != nil {
		return fmt.Errorf("write latest metrics: %w", err)
	}
	return nil
}

func writeJSON(path string, value any, mode os.FileMode) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'), mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".anqu-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
