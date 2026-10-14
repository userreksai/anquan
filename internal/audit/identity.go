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
type agentIdentity struct {
	ip      atomic.Pointer[string]
	localIP atomic.Pointer[string] // persisted TCP route identity, separate from an observed peer IP
}

func (c Config) reportedIP() string {
	if c.identity != nil {
		if ip := c.identity.ip.Load(); ip != nil {
			return *ip
		}
		return ""
	}
	return c.AgentIP
}

// A connected socket tells us which local interface the operating system chose
// for this route. This needs no public IP service or hostname interpretation.
func localSocketIP(address net.Addr) string {
	var ip net.IP
	switch address := address.(type) {
	case *net.TCPAddr:
		if address != nil {
			ip = address.IP
		}
	case *net.UDPAddr:
		if address != nil {
			ip = address.IP
		}
	default:
		return ""
	}
	return usableLocalIP(ip)
}

func usableLocalIP(ip net.IP) string {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ""
	}
	// IP.String canonicalizes IPv4-mapped IPv6 and compressed IPv6 addresses.
	return ip.String()
}

func retainedLocalIP(address string, interfaces []net.Addr) string {
	value := usableLocalIP(net.ParseIP(address))
	if value == "" {
		return ""
	}
	for _, address := range interfaces {
		var ip net.IP
		switch address := address.(type) {
		case *net.IPNet:
			if address != nil {
				ip = address.IP
			}
		case *net.IPAddr:
			if address != nil {
				ip = address.IP
			}
		}
		if usableLocalIP(ip) == value {
			return value
		}
	}
	return ""
}

func restoreLocalIdentity(identity *agentIdentity, settings connectionSettings) {
	if identity == nil || settings.Version != 3 || settings.LocalIP == "" {
		return
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	if value := retainedLocalIP(settings.LocalIP, interfaces); value != "" {
		identity.localIP.Store(&value)
		identity.ip.Store(&value)
	}
}

func (c Config) localIP() string {
	if c.identity != nil {
		if ip := c.identity.localIP.Load(); ip != nil {
			return *ip
		}
	}
	return ""
}

// Before a TCP route identity is available, the first usable UDP route wins
// across concurrent heartbeat/history workers and all configured UDP masters.
// TCP registration later replaces this temporary selection atomically.
func (c Config) udpReportedIP(address net.Addr) string {
	if value := c.reportedIP(); value != "" {
		return value
	}
	value := localSocketIP(address)
	if value == "" || c.identity == nil {
		return value
	}
	c.identity.ip.CompareAndSwap(nil, &value)
	return c.reportedIP()
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
