package cli

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
)

func ParseArgs(args []string) (*config.Config, error) {
	fs := flag.NewFlagSet("sip-tester", flag.ContinueOnError)

	cfg := &config.Config{}
	fs.StringVar(&cfg.CallerRaw, "caller", "", "caller SIP URI or user")
	fs.StringVar(&cfg.CalleeRaw, "callee", "", "callee SIP URI or user")
	fs.StringVar(&cfg.HostRaw, "host", "", "remote SIP host:port")
	fs.StringVar(&cfg.LocalIP, "local-ip", "", "local interface IP (literal)")
	fs.StringVar(&cfg.PCAP, "pcap", "", "pcap file path")
	fs.StringVar(&cfg.SSRCAudioRaw, "ssrc-audio", "", "audio SSRC (decimal or hex, e.g. 0x11223344)")
	fs.StringVar(&cfg.SSRCVideoRaw, "ssrc-video", "", "video SSRC (decimal or hex, e.g. 0x11223344)")
	fs.BoolVar(&cfg.Debug, "debug", false, "enable debug output")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if err := cfg.ValidateRequired(); err != nil {
		return nil, err
	}

	host, port, err := netutil.ParseHostPort(cfg.HostRaw)
	if err != nil {
		return nil, err
	}
	cfg.Host = host
	cfg.Port = port

	cfg.Caller, err = NormalizeURI(cfg.CallerRaw, cfg.HostRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid caller: %w", err)
	}

	cfg.Callee, err = NormalizeURI(cfg.CalleeRaw, cfg.HostRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid callee: %w", err)
	}

	ip := net.ParseIP(cfg.LocalIP)
	if ip == nil {
		return nil, fmt.Errorf("--local-ip must be a literal IP address")
	}
	cfg.LocalIPParsed = ip
	if ip.To4() != nil {
		cfg.IPFamily = "ipv4"
	} else {
		cfg.IPFamily = "ipv6"
	}

	if cfg.SSRCAudioRaw != "" {
		v, err := ParseSSRC(cfg.SSRCAudioRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid --ssrc-audio: %w", err)
		}
		cfg.SSRCAudio = &v
	}

	if cfg.SSRCVideoRaw != "" {
		v, err := ParseSSRC(cfg.SSRCVideoRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid --ssrc-video: %w", err)
		}
		cfg.SSRCVideo = &v
	}

	return cfg, nil
}

func ParseSSRC(raw string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	base := 10
	value := raw

	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		base = 16
		value = raw[2:]
	}
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}

	parsed, err := strconv.ParseUint(value, base, 32)
	if err != nil {
		return 0, fmt.Errorf("must be a valid uint32 decimal or hex")
	}

	return uint32(parsed), nil
}
