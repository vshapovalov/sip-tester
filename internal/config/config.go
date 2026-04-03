package config

import (
	"fmt"
	"net"

	"sip-tester/internal/netutil"
)

type Config struct {
	Mode string
	UA   string

	CallerRaw string
	CalleeRaw string
	HostRaw   string
	LocalIP   string
	PCAP      string

	SSRCAudioRaw string
	SSRCVideoRaw string
	Debug        bool
	Username     string
	Password     string

	Caller string
	Callee string
	Host   string
	Port   uint16

	LocalIPParsed net.IP
	IPFamily      netutil.IPFamily

	SSRCAudio *uint32
	SSRCVideo *uint32
}

func (c *Config) ValidateRequired() error {
	if c.Mode == "" {
		c.Mode = "outbound"
	}
	if c.UA == "" {
		c.UA = "sip-tester"
	}
	if c.Mode != "outbound" && c.Mode != "inbound" {
		return fmt.Errorf("--mode must be one of: outbound, inbound")
	}
	if c.CallerRaw == "" {
		return fmt.Errorf("--caller is required")
	}
	if c.Mode == "outbound" && c.CalleeRaw == "" {
		return fmt.Errorf("--callee is required")
	}
	if c.HostRaw == "" {
		return fmt.Errorf("--host is required")
	}
	if c.LocalIP == "" {
		return fmt.Errorf("--local-ip is required")
	}
	if c.PCAP == "" {
		return fmt.Errorf("--pcap is required")
	}
	if c.SSRCAudioRaw == "" && c.SSRCVideoRaw == "" {
		return fmt.Errorf("at least one of --ssrc-audio or --ssrc-video must be provided")
	}
	if (c.Username == "") != (c.Password == "") {
		return fmt.Errorf("--username and --password must be provided together")
	}
	return nil
}
