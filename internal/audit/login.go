package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectLogin(c LoginConfig, location *time.Location) (LoginResult, []Issue) {
	r := LoginResult{Enabled: c.Enabled, Success: true, Source: c.Source, Path: c.Path}
	if !c.Enabled {
		return r, nil
	}
	var err error
	if c.Source == "jsonl" {
		var f *os.File
		f, err = os.Open(c.Path)
		if err == nil {
			r.Record, err = parseJSONL(f)
			f.Close()
		}
	} else {
		r.Record, err = readWtmp(c)
	}
	if err != nil {
		r.Success = false
		return r, []Issue{{"login", err.Error()}}
	}
	if r.Record != nil {
		r.Record.LoginTime = r.Record.LoginTime.In(location)
	}
	return r, nil
}

func parseJSONL(reader io.Reader) (*LoginRecord, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var latest *LoginRecord
	line := 0
	for scanner.Scan() {
		line++
		b := bytes.TrimSpace(scanner.Bytes())
		if line == 1 {
			b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
		}
		if len(b) == 0 {
			continue
		}
		var record LoginRecord
		if err := json.Unmarshal(b, &record); err != nil {
			return nil, fmt.Errorf("JSONL line %d: %w", line, err)
		}
		if strings.TrimSpace(record.User) == "" || record.LoginTime.IsZero() || strings.TrimSpace(record.Terminal) == "" {
			return nil, fmt.Errorf("JSONL line %d: user, RFC3339 login_time and terminal are required (use N/A for no terminal)", line)
		}
		if record.SourceIP != "" && net.ParseIP(record.SourceIP) == nil {
			return nil, fmt.Errorf("JSONL line %d: invalid source_ip", line)
		}
		if latest == nil || !record.LoginTime.Before(latest.LoginTime) {
			copy := record
			latest = &copy
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read JSONL: %w", err)
	}
	return latest, nil
}

// Capped output prevents an unexpected last implementation from exhausting memory.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, fmt.Errorf("command output exceeds %d bytes", b.max)
	}
	return b.Buffer.Write(p)
}

func readWtmp(c LoginConfig) (*LoginRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.LastCommand, "-w", "-i", "--time-format", "iso", "-n", strconv.Itoa(c.MaxRecords), "-f", c.Path)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	stdout := &cappedBuffer{max: 32 * 1024 * 1024}
	stderr := &cappedBuffer{max: 64 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("last timed out after %d seconds", c.TimeoutSeconds)
		}
		return nil, fmt.Errorf("last failed (requires util-linux last with --time-format iso): %w; %s", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return nil, fmt.Errorf("last reported a warning: %s", strings.TrimSpace(stderr.String()))
	}
	return parseLast(stdout.String())
}

func parseLast(output string) (*LoginRecord, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) >= 2 && fields[1] == "begins" {
			continue
		}
		if fields[0] == "reboot" || fields[0] == "shutdown" || fields[0] == "runlevel" {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("unrecognized last output: %q", line)
		}
		dateIndex := -1
		var loginTime time.Time
		for i := 2; i < len(fields); i++ {
			if t, err := time.Parse(time.RFC3339, fields[i]); err == nil {
				dateIndex, loginTime = i, t
				break
			}
		}
		if dateIndex != 2 && dateIndex != 3 {
			return nil, fmt.Errorf("invalid last columns/ISO time: %q", line)
		}
		ip := ""
		if dateIndex == 3 {
			ip = fields[2]
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return nil, fmt.Errorf("last returned a non-IP host %q", ip)
			}
			if parsed.IsUnspecified() {
				ip = ""
			}
		}
		return &LoginRecord{User: fields[0], Terminal: fields[1], SourceIP: ip, LoginTime: loginTime}, nil
	}
	return nil, nil
}
