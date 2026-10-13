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
	host, port := address, defaultPort
	if ip := net.ParseIP(address); ip != nil {
		host = ip.String()
	} else if strings.Contains(address, ":") {
		var err error
		host, port, err = net.SplitHostPort(address)
		if err != nil {
			return "", invalidEndpoint(address)
		}
	}
	n, portErr := strconv.Atoi(port)
	if portErr != nil || n < 1 || n > 65535 || strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return "", invalidEndpoint(address)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", invalidEndpoint(address)
		}
		host = ip.String()
	} else {
		// Keep hostnames unresolved so startup works while DNS/master is offline,
		// and every reconnect/send can resolve the current destination.
		if strings.ContainsAny(address, "[]") || !validEndpointHostname(host) {
			return "", invalidEndpoint(address)
		}
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func invalidEndpoint(address string) error {
	return fmt.Errorf("address must be an IP or DNS hostname, optionally with a port (IPv6 ports in brackets): %q", address)
}

func validEndpointHostname(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	hasLetter := false
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			switch {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
				hasLetter = true
			case ch >= '0' && ch <= '9', ch == '-':
			default:
				return false
			}
		}
	}
	// Numeric IP lookalikes must not bypass IP validation through DNS.
	return hasLetter
}
