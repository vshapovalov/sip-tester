package netutil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseHostPort validates and parses host:port for IPv4, IPv6, and DNS hostnames.
func ParseHostPort(value string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host %q: %w", value, err)
	}

	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if strings.TrimSpace(h) == "" {
		return "", 0, fmt.Errorf("invalid host %q: host is empty", value)
	}

	portNum, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host %q: invalid port %q", value, p)
	}

	return h, uint16(portNum), nil
}
