package cli

import (
	"fmt"
	"strings"

	"sip-tester/internal/netutil"
)

func NormalizeURI(raw, hostPort string) (string, error) {
	if strings.HasPrefix(raw, "sip:") {
		return raw, nil
	}

	host, _, err := netutil.ParseHostPort(hostPort)
	if err != nil {
		return "", fmt.Errorf("normalize URI: %w", err)
	}

	return fmt.Sprintf("sip:%s@%s", raw, host), nil
}
