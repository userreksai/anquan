package audit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Prometheus label escaping differs from Go quoting (notably for tabs and UTF-8).
func label(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	return "\"" + r.Replace(s) + "\""
}

func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}

func metrics(r Report) []byte {
	var b strings.Builder
	gauge := func(name, help string, value any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
	}
	header := func(name, help, kind string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind) }
	gauge("anqu_collection_success", "Whether every enabled collection module succeeded.", bit(r.Success))
	gauge("anqu_run_timestamp_seconds", "Unix time of the latest collection attempt.", r.FinishedAt.Unix())
	gauge("anqu_run_duration_seconds", "Collection duration in seconds excluding output writes.", strconv.FormatFloat(r.FinishedAt.Sub(r.StartedAt).Seconds(), 'f', 6, 64))
	gauge("anqu_collection_errors", "Number of collection or state errors in this run.", len(r.Errors))
	header("anqu_module_enabled", "Whether a collection module is enabled.", "gauge")
	fmt.Fprintf(&b, "anqu_module_enabled{module=\"md5\"} %d\nanqu_module_enabled{module=\"login\"} %d\nanqu_module_enabled{module=\"existence\"} %d\n", bit(r.MD5.Enabled), bit(r.Login.Enabled), bit(r.Existence.Enabled))
	fmt.Fprintf(&b, "anqu_module_enabled{module=\"files\"} %d\nanqu_module_enabled{module=\"processes\"} %d\n", bit(r.Files.Enabled), bit(r.Processes.Enabled))
	header("anqu_module_success", "Whether the module collected successfully; disabled modules return one.", "gauge")
	fmt.Fprintf(&b, "anqu_module_success{module=\"md5\"} %d\nanqu_module_success{module=\"login\"} %d\nanqu_module_success{module=\"existence\"} %d\n", bit(r.MD5.Success), bit(r.Login.Success), bit(r.Existence.Success))
	fmt.Fprintf(&b, "anqu_module_success{module=\"files\"} %d\nanqu_module_success{module=\"processes\"} %d\n", bit(r.Files.Success), bit(r.Processes.Success))
	gauge("anqu_alerts", "Number of alerts in this scan.", len(r.Alerts))
	if r.Files.Enabled {
		gauge("anqu_files_scanned", "Files hashed in this scan.", r.Files.Scanned)
		header("anqu_files_check", "Per-file result, including missing and hash mismatches.", "gauge")
		for _, item := range r.Files.Items {
			fmt.Fprintf(&b, "anqu_files_check{path=%s,rule=%s,mode=%s,status=%s} 1\n", label(item.Path), label(item.Rule), label(item.Mode), label(item.Status))
		}
		header("anqu_files_change", "Changed files relative to the previous successful scan.", "gauge")
		for _, item := range r.Files.Changes {
			fmt.Fprintf(&b, "anqu_files_change{path=%s,kind=%s} 1\n", label(item.Path), label(item.Kind))
		}
	}
	if r.Processes.Enabled {
		gauge("anqu_processes_scanned", "Running process instances excluding this agent.", r.Processes.Scanned)
		gauge("anqu_processes_missing", "Required command groups with no running match.", r.Processes.Missing)
		header("anqu_process_exists", "One if any command in the configured group is running.", "gauge")
		for _, item := range r.Processes.Items {
			fmt.Fprintf(&b, "anqu_process_exists{rule=%s} %d\n", label(item.Rule), bit(item.Exists))
		}
		header("anqu_process_instances", "Instances by full command, including whitelisted commands.", "gauge")
		for _, item := range r.Processes.Inventory {
			fmt.Fprintf(&b, "anqu_process_instances{command=%s,whitelisted=%s} %d\n", label(item.Command), label(strconv.FormatBool(item.Whitelisted)), item.Count)
		}
	}
	if r.Login.Enabled {
		gauge("anqu_ssh_logins_new", "Previously unreported successful login records collected this run.", len(r.Login.Records))
		gauge("anqu_ssh_logins_pending", "One when another page of login data may remain.", bit(r.Login.Pending))
		header("anqu_ssh_login_timestamp_seconds", "Time of each newly observed login.", "gauge")
		for i, item := range r.Login.Records {
			fmt.Fprintf(&b, "anqu_ssh_login_timestamp_seconds{id=%s,user=%s,source_ip=%s,terminal=%s} %d\n", label(item.ID+":"+strconv.Itoa(i)), label(item.User), label(item.SourceIP), label(item.Terminal), item.LoginTime.Unix())
		}
	}
	if r.MD5.Enabled && r.MD5.Success {
		gauge("anqu_md5_files", "Number of regular files hashed in this run.", r.MD5.Scanned)
		gauge("anqu_md5_skipped", "Number of symbolic links and special files skipped.", r.MD5.Skipped)
		gauge("anqu_md5_missing_roots", "Number of configured paths currently absent after baseline creation.", len(r.MD5.MissingRoots))
		gauge("anqu_md5_baseline_created", "One when this run created the first baseline.", bit(r.MD5.BaselineCreated))
		counts := map[string]int{}
		for _, change := range r.MD5.Changes {
			counts[change.Kind]++
		}
		header("anqu_md5_changes", "File changes versus the previous successful MD5 scan.", "gauge")
		for _, kind := range []string{"added", "modified", "deleted"} {
			fmt.Fprintf(&b, "anqu_md5_changes{kind=%s} %d\n", label(kind), counts[kind])
		}
		header("anqu_md5_changes_total", "Persisted observed file changes since the baseline was created.", "counter")
		for _, kind := range []string{"added", "modified", "deleted"} {
			fmt.Fprintf(&b, "anqu_md5_changes_total{kind=%s} %d\n", label(kind), r.MD5.Cumulative[kind])
		}
		lastChange := int64(0)
		if r.MD5.LastChange != nil {
			lastChange = r.MD5.LastChange.Unix()
		}
		gauge("anqu_md5_last_change_timestamp_seconds", "Unix time of the most recently observed MD5 change, or zero.", lastChange)
		header("anqu_md5_file_change", "Files changed during this run; hashes are in the JSON report.", "gauge")
		for _, change := range r.MD5.Changes {
			fmt.Fprintf(&b, "anqu_md5_file_change{path=%s,kind=%s} 1\n", label(change.Path), label(change.Kind))
		}
	}
	if r.Login.Enabled && r.Login.Success {
		gauge("anqu_login_found", "Whether the configured source contains a login record.", bit(r.Login.Record != nil))
		if v := r.Login.Record; v != nil {
			gauge("anqu_last_login_timestamp_seconds", "Unix time of the latest login in the configured source.", v.LoginTime.Unix())
			header("anqu_last_login_info", "Identity, source IP and terminal of the latest login.", "gauge")
			fmt.Fprintf(&b, "anqu_last_login_info{user=%s,source_ip=%s,terminal=%s} 1\n", label(v.User), label(v.SourceIP), label(v.Terminal))
		}
	}
	if r.Existence.Enabled {
		gauge("anqu_existence_checked", "Number of entries checked from the configured list.", len(r.Existence.Items))
		gauge("anqu_existence_missing", "Entries confirmed missing in this run.", r.Existence.Missing)
		gauge("anqu_existence_type_mismatch", "Existing entries with the wrong type.", r.Existence.TypeMismatch)
		header("anqu_file_check_success", "Whether the path could be inspected; absence is a valid result.", "gauge")
		for _, v := range r.Existence.Items {
			fmt.Fprintf(&b, "anqu_file_check_success{path=%s,type=%s} %d\n", label(v.Path), label(v.ExpectedType), bit(v.Error == ""))
		}
		header("anqu_file_exists", "Whether the configured path exists; unreadable paths have no sample.", "gauge")
		for _, v := range r.Existence.Items {
			if v.Error == "" {
				fmt.Fprintf(&b, "anqu_file_exists{path=%s,type=%s} %d\n", label(v.Path), label(v.ExpectedType), bit(v.Exists))
			}
		}
		header("anqu_file_matches", "Whether the path exists and has the required type.", "gauge")
		for _, v := range r.Existence.Items {
			if v.Error == "" {
				fmt.Fprintf(&b, "anqu_file_matches{path=%s,type=%s} %d\n", label(v.Path), label(v.ExpectedType), bit(v.Matches))
			}
		}
	}
	return []byte(b.String())
}

// Monitoring metrics retain their collection identity and separate namespace
// so they can share a collector directory with latest-state metrics.
func snapshotMetrics(r Report, source []byte) []byte {
	var out strings.Builder
	labels := "host=" + label(r.Host) + ",run_id=" + label(r.StartedAt.Format(time.RFC3339Nano))
	for _, line := range strings.Split(string(source), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			line = strings.Replace(line, "anqu_", "anqu_snapshot_", 1)
		} else {
			line = strings.Replace(line, "anqu_", "anqu_snapshot_", 1)
			if i := strings.IndexByte(line, '{'); i >= 0 {
				line = line[:i+1] + labels + "," + line[i+1:]
			} else if i := strings.IndexByte(line, ' '); i >= 0 {
				line = line[:i] + "{" + labels + "}" + line[i:]
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}
