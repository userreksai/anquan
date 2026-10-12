package audit

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// Shared by immutable runtime config copies, so reconnect discovery updates
// heartbeats, scans and history together without racing independent workers.
type agentIdentity struct{ ip atomic.Pointer[string] }

func (c Config) reportedIP() string {
	if c.identity != nil {
		if ip := c.identity.ip.Load(); ip != nil {
			return *ip
		}
		return ""
	}
	return c.AgentIP
}

func normalizeEndpoint(address, defaultPort string) (string, error) {
	address = strings.TrimSpace(address)
	if ip := net.ParseIP(address); ip != nil {
		address = net.JoinHostPort(ip.String(), defaultPort)
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || ip.IsUnspecified() || ip.IsMulticast() || portErr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("address must be an IP or IP:port (IPv6 ports in brackets): %q", address)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}
