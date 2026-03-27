package config

import (
	"fmt"
	"net"
)

type Config struct {
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
	IPFamily      string

	SSRCAudio *uint32
	SSRCVideo *uint32
}

func (c *Config) ValidateRequired() error {
	if c.CallerRaw == "" {
		return fmt.Errorf("--caller is required")
	}
	if c.CalleeRaw == "" {
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
