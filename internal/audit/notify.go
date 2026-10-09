package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Version 1 remains additive: old masters may ignore ip and new summary fields.
// Each datagram is one complete event, not a batch or a fragment.
type udpEnvelope struct {
	Version      int             `json:"version"`
	EventID      string          `json:"event_id"`
	IP           string          `json:"ip"`
	Host         string          `json:"host"`
	Time         time.Time       `json:"time"`
	Type         string          `json:"type"`
	Data         json.RawMessage `json:"data"`
	AckRequested bool            `json:"ack_requested,omitempty"`
}

func udpMessages(c Config, r Report, ip string) ([][]byte, error) {
	var messages [][]byte
	add := func(kind string, at time.Time, stableID string, data any) error {
		b, err := encodeUDPEvent(ip, r.Host, kind, at, stableID, data)
		if err != nil {
			return err
		}
		messages = append(messages, b)
		return nil
	}
	// Every completed scan sends a summary, even when there are no findings.
	// Legacy masters can also use it as a heartbeat. New agents additionally
	// send an independent heartbeat so slow scans cannot delay presence updates.
	if err := add("scan_summary", r.StartedAt, "", struct {
		Success         bool      `json:"collection_success"`
		Alerts          int       `json:"alerts"`
		Errors          int       `json:"errors"`
		Files           int       `json:"files"`
		Processes       int       `json:"processes"`
		Logins          int       `json:"logins"`
		LoginPending    bool      `json:"login_pending"`
		IntervalSeconds int       `json:"interval_seconds"`
		FinishedAt      time.Time `json:"finished_at"`
	}{r.Success, len(r.Alerts), len(r.Errors), r.Files.Scanned, r.Processes.Scanned, len(r.Login.Records), r.Login.Pending, int(c.Interval().Seconds()), r.FinishedAt}); err != nil {
		return nil, err
	}
	for _, alert := range r.Alerts {
		if err := add("alert", r.StartedAt, "", alert); err != nil {
			return nil, err
		}
	}
	for _, record := range r.Login.Records {
		// The durable login ID survives a failed publication and the next scan.
		// Without an ID, the original login timestamp/body is still deterministic.
		if err := add("ssh_login", record.LoginTime, record.ID, record); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

const HeartbeatInterval = 30 * time.Second

func encodeUDPEvent(ip, host, kind string, at time.Time, stableID string, data any) ([]byte, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	identity := []byte(ip + "\x00" + host + "\x00" + kind + "\x00")
	if stableID != "" {
		identity = append(identity, stableID...)
	} else {
		identity = append(identity, at.UTC().Format(time.RFC3339Nano)+"\x00"...)
		identity = append(identity, body...)
	}
	id := sha256.Sum256(identity)
	return json.Marshal(udpEnvelope{Version: 1, EventID: hex.EncodeToString(id[:]), IP: ip, Host: host, Time: at, Type: kind, Data: body})
}

// NotifyHeartbeat announces this agent without waiting for file/process/login
// collection. The internal-network protocol intentionally has no credentials or
// encryption. Delivery is best effort, just like other UDP notifications.
func NotifyHeartbeat(c Config, version string) []NotificationResult {
	host, hostErr := os.Hostname()
	at := time.Now().UTC()
	return sendUDP(c, func(ip string) ([][]byte, error) {
		if hostErr != nil {
			return nil, hostErr
		}
		b, err := encodeUDPEvent(ip, host, "heartbeat", at, "", struct {
			IntervalSeconds int    `json:"interval_seconds"`
			State           string `json:"state"`
			Version         string `json:"version,omitempty"`
		}{int(HeartbeatInterval.Seconds()), "running", version})
		return [][]byte{b}, err
	})
}

// UDP is a best-effort transport. A successful Write means local send only;
// it is never reported as master acknowledgement or delivery confirmation.
func notifyServers(c Config, r Report) []NotificationResult {
	return sendUDP(c, func(ip string) ([][]byte, error) { return udpMessages(c, r, ip) })
}

func sendUDP(c Config, messagesForIP func(string) ([][]byte, error)) []NotificationResult {
	results := []NotificationResult{}
	for _, endpoint := range c.Server {
		result := NotificationResult{Server: endpoint}
		conn, err := net.DialTimeout("udp", endpoint, 2*time.Second)
		if err == nil {
			result.IP = c.AgentIP
			if result.IP == "" {
				result.IP = conn.LocalAddr().(*net.UDPAddr).IP.String()
			}
			var messages [][]byte
			messages, err = messagesForIP(result.IP)
			if err == nil {
				for _, b := range messages {
					if len(b) > 60000 {
						err = fmt.Errorf("UDP event exceeds 60000 bytes; complete event retained in local log/report")
						break
					}
					if err = conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
						break
					}
					if _, err = conn.Write(b); err != nil {
						break
					}
					result.Sent++
				}
			}
			conn.Close()
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	return results
}
