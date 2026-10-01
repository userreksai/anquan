package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func Run(c Config) (Report, OutputPaths, error) {
	r := Report{Version: 1, Success: true, Errors: []Issue{}}
	var paths OutputPaths
	if c.location == nil {
		return r, paths, fmt.Errorf("configuration must be loaded with LoadConfig")
	}
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
	r.StartedAt = time.Now().In(c.location)
	r.Host, err = os.Hostname()
	if err != nil {
		r.Errors = append(r.Errors, Issue{"host", err.Error()})
	}
	var issues []Issue
	var next *baseline
	r.MD5, next, issues = collectMD5(c, r.StartedAt)
	r.Errors = append(r.Errors, issues...)
	r.Login, issues = collectLogin(c.Login, c.location)
	r.Errors = append(r.Errors, issues...)
	r.Existence, issues = collectExistence(c.Existence)
	r.Errors = append(r.Errors, issues...)
	r.FinishedAt = time.Now().In(c.location)
	r.Success = len(r.Errors) == 0
	stamp := r.StartedAt.Format("20060102_150405.000000000-0700")
	paths = OutputPaths{
		JSON:   filepath.Join(c.OutputDir, stamp+".json"),
		Prom:   filepath.Join(c.OutputDir, stamp+".prom"),
		Latest: filepath.Join(c.OutputDir, "textfile", "anqu.prom"),
	}
	if err := publish(r, paths); err != nil {
		return r, paths, err
	}
	// Commit only after the reports have been published. A crash before this point
	// may repeat a change next time, but cannot silently consume an unreported change.
	if next != nil {
		if err := writeJSON(c.StateFile, next, 0600); err != nil {
			r.Success, r.MD5.Success, r.MD5.BaselineCreated = false, false, false
			r.Errors = append(r.Errors, Issue{"md5", "save baseline: " + err.Error()})
			if err := publish(r, paths); err != nil {
				return r, paths, err
			}
		}
	}
	return r, paths, nil
}

func publish(r Report, paths OutputPaths) error {
	if err := writeJSON(paths.JSON, r, 0640); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	b := metrics(r)
	if err := atomicWrite(paths.Prom, b, 0644); err != nil {
		return fmt.Errorf("write archive metrics: %w", err)
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
