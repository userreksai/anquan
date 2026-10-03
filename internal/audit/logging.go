package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func logPath(c Config, now time.Time) string {
	template := filepath.Join(c.OutputDir, "logs", "时间anquan.log")
	if c.Setup != nil {
		template = c.Setup.Logs
	}
	return datedOutput(template, now, true)
}

// JSON Lines keeps paths/commands unambiguous and escapes embedded newlines.
func writeLog(c Config, writer io.Writer, now time.Time, event string, data any) error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	entry := struct {
		Time  time.Time `json:"time"`
		Host  string    `json:"host"`
		Event string    `json:"event"`
		Data  any       `json:"data"`
	}{now.In(beijing), host, event, data}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	p := logPath(c, now)
	if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if writer != nil {
		_, err = writer.Write(b)
	}
	return err
}

func LifecycleLog(c Config, writer io.Writer, event string, detail any) error {
	return writeLog(c, writer, time.Now(), event, detail)
}

func writeReportLog(c Config, writer io.Writer, r Report) error {
	// Include the complete result for every enabled module, including normal files
	// and full process inventory, plus separate searchable alert/login entries.
	for _, module := range []struct {
		name    string
		data    any
		enabled bool
	}{
		{"files_result", r.Files, r.Files.Enabled}, {"process_result", r.Processes, r.Processes.Enabled},
		{"md5_result", r.MD5, r.MD5.Enabled}, {"existence_result", r.Existence, r.Existence.Enabled},
		{"login_result", r.Login, r.Login.Enabled},
	} {
		if module.enabled {
			if err := writeLog(c, writer, time.Now(), module.name, module.data); err != nil {
				return err
			}
		}
	}
	for _, entry := range r.Login.Records {
		if err := writeLog(c, writer, time.Now(), "ssh_login", entry); err != nil {
			return err
		}
	}
	for _, entry := range r.Alerts {
		if err := writeLog(c, writer, time.Now(), "alert", entry); err != nil {
			return err
		}
	}
	return nil
}

func writeScanComplete(c Config, writer io.Writer, r Report) error {
	return writeLog(c, writer, time.Now(), "scan_complete", struct {
		StartedAt     time.Time            `json:"started_at"`
		FinishedAt    time.Time            `json:"finished_at"`
		Success       bool                 `json:"collection_success"`
		AlertCount    int                  `json:"alert_count"`
		Errors        []Issue              `json:"errors"`
		Notifications []NotificationResult `json:"notifications"`
	}{r.StartedAt, r.FinishedAt, r.Success, len(r.Alerts), r.Errors, r.Notifications})
}

func logRunFailure(c Config, writer io.Writer, err error) error {
	if logErr := LifecycleLog(c, writer, "scan_failed", map[string]string{"error": err.Error()}); logErr != nil {
		return fmt.Errorf("%w; write failure log: %v", err, logErr)
	}
	return err
}
