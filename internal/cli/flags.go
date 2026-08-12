package cli

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
)

func ParseArgs(args []string) (*config.Config, error) {
	fs := flag.NewFlagSet("sip-tester", flag.ContinueOnError)

	cfg := &config.Config{}
	cfg.Headers = make(map[string]string)
	var cancelAfterRaw string
	var answerAfterRaw string
	var rejectAfterRaw string
	var registeredWaitRaw string
	fs.StringVar(&cfg.Mode, "mode", "outbound", "call mode: outbound|inbound")
	fs.StringVar(&cfg.UA, "ua", "sip-tester", "SIP User-Agent header value")
	fs.StringVar(&cfg.CallerRaw, "caller", "", "caller SIP URI or user")
	fs.StringVar(&cfg.CalleeRaw, "callee", "", "callee SIP URI or user")
	fs.StringVar(&cfg.HostRaw, "host", "", "remote SIP host:port")
	fs.StringVar(&cfg.LocalIP, "local-ip", "", "local interface IP (literal)")
	fs.StringVar(&cfg.PCAP, "pcap", "", "pcap file path")
	fs.StringVar(&cfg.SSRCAudioRaw, "ssrc-audio", "", "audio SSRC (decimal or hex, e.g. 0x11223344)")
	fs.StringVar(&cfg.SSRCVideoRaw, "ssrc-video", "", "video SSRC (decimal or hex, e.g. 0x11223344)")
	fs.BoolVar(&cfg.Debug, "debug", false, "enable debug output")
	fs.StringVar(&cfg.Username, "username", "", "SIP digest auth username")
	fs.StringVar(&cfg.Password, "password", "", "SIP digest auth password")
	fs.Func("header", "additional SIP header in name:value form (repeatable)", func(raw string) error {
		name, headerValue, found := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		headerValue = strings.TrimSpace(headerValue)
		if !found || name == "" || headerValue == "" {
			return fmt.Errorf("--header must use non-empty name:value form")
		}
		if err := validateAdditionalSIPHeader(name, headerValue); err != nil {
			return err
		}
		for existingName := range cfg.Headers {
			if strings.EqualFold(existingName, name) {
				return fmt.Errorf("duplicate header %q", name)
			}
		}
		cfg.Headers[name] = headerValue
		return nil
	})
	fs.StringVar(&cancelAfterRaw, "cancel-after", "", "cancel a pending outbound INVITE after this duration")
	fs.StringVar(&answerAfterRaw, "answer-after", "", "answer an inbound INVITE after this duration")
	fs.StringVar(&rejectAfterRaw, "reject-after", "", "reject an inbound INVITE with 486 Busy Here after this duration")
	fs.StringVar(&registeredWaitRaw, "registered-wait", "", "remain registered without answering for this duration")
	fs.BoolVar(&cfg.EarlyMedia, "early-media", false, "send 183 Session Progress with SDP before answering an inbound INVITE")
	fs.IntVar(&cfg.RequireEarlyVideoPackets, "require-early-video-packets", 0, "require this many video RTP packets before answering an inbound INVITE")
	fs.IntVar(&cfg.RequireFinalVideoPackets, "require-final-video-packets", 0, "require this many new video RTP packets after answering an inbound INVITE")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	var err error
	if cfg.CancelAfter, err = parsePositiveDuration("--cancel-after", cancelAfterRaw); err != nil {
		return nil, err
	}
	if cfg.AnswerAfter, err = parsePositiveDuration("--answer-after", answerAfterRaw); err != nil {
		return nil, err
	}
	if cfg.RejectAfter, err = parsePositiveDuration("--reject-after", rejectAfterRaw); err != nil {
		return nil, err
	}
	if cfg.RegisteredWait, err = parsePositiveDuration("--registered-wait", registeredWaitRaw); err != nil {
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

	if cfg.CalleeRaw != "" {
		cfg.Callee, err = NormalizeURI(cfg.CalleeRaw, cfg.HostRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid callee: %w", err)
		}
	}

	ip := net.ParseIP(cfg.LocalIP)
	if ip == nil {
		return nil, fmt.Errorf("--local-ip must be a literal IP address")
	}
	cfg.LocalIPParsed = ip
	cfg.IPFamily, err = netutil.DetectIPFamily(ip)
	if err != nil {
		return nil, fmt.Errorf("detect local-ip family: %w", err)
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

func validateAdditionalSIPHeader(name, headerValue string) error {
	for _, character := range name {
		isAlphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		isTokenPunctuation := strings.ContainsRune("-.!%*_+`'~", character)
		if !isAlphaNumeric && !isTokenPunctuation {
			return fmt.Errorf("invalid SIP header name %q", name)
		}
	}
	if strings.ContainsAny(headerValue, "\r\n") {
		return fmt.Errorf("invalid header value for %q: line breaks are not allowed", name)
	}
	switch strings.ToLower(name) {
	case "via", "max-forwards", "from", "to", "call-id", "cseq", "contact", "content-type", "content-length", "user-agent", "route", "record-route", "authorization", "proxy-authorization":
		return fmt.Errorf("SIP header %q is managed by sip-tester", name)
	default:
		return nil
	}
}

func parsePositiveDuration(flagName, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", flagName, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", flagName)
	}
	return duration, nil
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
