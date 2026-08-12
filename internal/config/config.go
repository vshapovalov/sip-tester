package config

import (
	"fmt"
	"net"
	"time"

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

	SSRCAudioRaw             string
	SSRCVideoRaw             string
	Debug                    bool
	Username                 string
	Password                 string
	Headers                  map[string]string
	CancelAfter              time.Duration
	AnswerAfter              time.Duration
	RejectAfter              time.Duration
	RegisteredWait           time.Duration
	EarlyMedia               bool
	RequireEarlyVideoPackets int
	RequireFinalVideoPackets int

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
	if c.Mode == "inbound" && c.CancelAfter > 0 {
		return fmt.Errorf("--cancel-after is only valid in outbound mode")
	}
	if c.Mode == "outbound" && c.AnswerAfter > 0 {
		return fmt.Errorf("--answer-after is only valid in inbound mode")
	}
	if c.Mode == "outbound" && c.RejectAfter > 0 {
		return fmt.Errorf("--reject-after is only valid in inbound mode")
	}
	if c.AnswerAfter > 0 && c.RejectAfter > 0 {
		return fmt.Errorf("--answer-after and --reject-after cannot be used together")
	}
	if c.Mode == "outbound" && c.RegisteredWait > 0 {
		return fmt.Errorf("--registered-wait is only valid in inbound mode")
	}
	if c.Mode == "outbound" && c.EarlyMedia {
		return fmt.Errorf("--early-media is only valid in inbound mode")
	}
	if c.RequireEarlyVideoPackets < 0 {
		return fmt.Errorf("--require-early-video-packets cannot be negative")
	}
	if c.RequireEarlyVideoPackets > 0 && !c.EarlyMedia {
		return fmt.Errorf("--require-early-video-packets requires --early-media")
	}
	if c.RequireEarlyVideoPackets > 0 && c.SSRCVideoRaw == "" {
		return fmt.Errorf("--require-early-video-packets requires --ssrc-video")
	}
	if c.RequireFinalVideoPackets < 0 {
		return fmt.Errorf("--require-final-video-packets cannot be negative")
	}
	if c.Mode == "outbound" && c.RequireFinalVideoPackets > 0 {
		return fmt.Errorf("--require-final-video-packets is only valid in inbound mode")
	}
	if c.RequireFinalVideoPackets > 0 && c.SSRCVideoRaw == "" {
		return fmt.Errorf("--require-final-video-packets requires --ssrc-video")
	}
	if c.RequireFinalVideoPackets > 0 && c.RejectAfter > 0 {
		return fmt.Errorf("--require-final-video-packets cannot be used with --reject-after")
	}
	return nil
}
