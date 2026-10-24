package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const maxSSHAccountUsers = 256
const maxSSHAccountInventoryBytes = 16 * 1024
const maxSSHAccountSourceBytes = 2 * 1024 * 1024

var sshAccountName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$`)

// Account discovery is a read-only local passwd inventory, not an SSH access
// decision. Passwords, shadow data and user-controlled descriptive fields never
// leave the host. PAM, account locking, keys and NSS can further affect login.
type sshAccount struct {
	Name       string `json:"name"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Shell      string `json:"shell"`
	LoginShell bool   `json:"login_shell"`
}

type sshAccountInventory struct {
	State     string       `json:"state"`
	Source    string       `json:"source"`
	CheckedAt time.Time    `json:"checked_at"`
	Total     int          `json:"total"`
	Truncated bool         `json:"truncated"`
	Users     []sshAccount `json:"users"`
	Error     string       `json:"error,omitempty"`
}

func hostSSHAccounts() sshAccountInventory {
	if runtime.GOOS != "linux" {
		return sshAccountInventory{
			State: "unsupported", Source: "/etc/passwd", CheckedAt: time.Now().UTC(),
			Users: []sshAccount{}, Error: "Local SSH account discovery requires Linux",
		}
	}
	return readSSHAccounts("/etc/passwd", time.Now().UTC())
}

func readSSHAccounts(path string, checkedAt time.Time) sshAccountInventory {
	result := sshAccountInventory{State: "ready", Source: "/etc/passwd", CheckedAt: checkedAt.UTC(), Users: []sshAccount{}}
	fail := func(message string) sshAccountInventory {
		result.State, result.Error = "error", message
		result.Users, result.Total, result.Truncated = []sshAccount{}, 0, false
		return result
	}
	file, err := os.Open(path)
	if err != nil {
		return fail("Cannot read local account database")
	}
	defer file.Close()
	limited := &io.LimitedReader{R: file, N: maxSSHAccountSourceBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	users := []sshAccount{}
	seen := map[string]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || len(fields[0]) > 128 || !sshAccountName.MatchString(fields[0]) ||
			len(fields[6]) > 256 || strings.ContainsFunc(fields[6], unicode.IsControl) || seen[fields[0]] {
			return fail("Local account database contains invalid or duplicate entries")
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			return fail("Local account database contains invalid numeric identifiers")
		}
		seen[fields[0]] = true
		shell := fields[6]
		interactive := true
		switch filepath.Base(shell) {
		case "false", "nologin", "sync", "shutdown", "halt":
			interactive = false
		}
		users = append(users, sshAccount{fields[0], uint32(uid), uint32(gid), shell, interactive})
	}
	if err := scanner.Err(); err != nil || limited.N <= 0 {
		return fail("Local account database exceeds the read limit or could not be read completely")
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].LoginShell != users[j].LoginShell {
			return users[i].LoginShell
		}
		if users[i].UID != users[j].UID {
			return users[i].UID < users[j].UID
		}
		return users[i].Name < users[j].Name
	})
	result.Total = len(users)
	result.Users = users[:min(len(users), maxSSHAccountUsers)]
	result.Truncated = len(result.Users) < result.Total
	for {
		data, err := json.Marshal(result)
		if err != nil {
			return fail(fmt.Sprintf("Cannot encode local account inventory: %v", err))
		}
		if len(data) <= maxSSHAccountInventoryBytes {
			return result
		}
		result.Users = result.Users[:len(result.Users)-1]
		result.Truncated = true
	}
}
