package sipclient

import (
	"fmt"
	"strconv"
	"strings"
)

type InfoPayload struct {
	ContentType string
	Body        string
}

type SDPAnswer struct {
	ConnectionIP string
	Media        []SDPMedia
}

type SDPMedia struct {
	Type         string
	Port         int
	ConnectionIP string
	Protocol     string
	Formats      []string
	RTPMap       map[string]string
	FMTP         map[string]string
}

func ParseSDP(raw string) (SDPAnswer, error) {
	lines := strings.Split(raw, "\n")
	answer := SDPAnswer{Media: make([]SDPMedia, 0, 2)}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "c="):
			fields := strings.Fields(strings.TrimPrefix(line, "c="))
			if len(fields) >= 3 {
				if len(answer.Media) == 0 {
					answer.ConnectionIP = fields[2]
				} else {
					answer.Media[len(answer.Media)-1].ConnectionIP = fields[2]
				}
			}
		case strings.HasPrefix(line, "m="):
			m, err := parseSDPMediaLine(strings.TrimPrefix(line, "m="))
			if err != nil {
				return SDPAnswer{}, err
			}
			answer.Media = append(answer.Media, m)
		case strings.HasPrefix(line, "a=rtpmap:"):
			if len(answer.Media) == 0 {
				continue
			}
			pt, codec, ok := parseAttributeKV(strings.TrimPrefix(line, "a=rtpmap:"))
			if ok {
				answer.Media[len(answer.Media)-1].RTPMap[pt] = codec
			}
		case strings.HasPrefix(line, "a=fmtp:"):
			if len(answer.Media) == 0 {
				continue
			}
			pt, cfg, ok := parseAttributeKV(strings.TrimPrefix(line, "a=fmtp:"))
			if ok {
				answer.Media[len(answer.Media)-1].FMTP[pt] = cfg
			}
		}
	}

	if len(answer.Media) == 0 {
		return SDPAnswer{}, fmt.Errorf("SDP has no media sections")
	}
	return answer, nil
}

func ParseSDPAnswer(raw string) (SDPAnswer, error) {
	return ParseSDP(raw)
}

func parseSDPMediaLine(raw string) (SDPMedia, error) {
	parts := strings.Fields(raw)
	if len(parts) < 4 {
		return SDPMedia{}, fmt.Errorf("invalid SDP media line: %q", raw)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return SDPMedia{}, fmt.Errorf("invalid media port %q", parts[1])
	}

	return SDPMedia{
		Type:     parts[0],
		Port:     port,
		Protocol: parts[2],
		Formats:  parts[3:],
		RTPMap:   map[string]string{},
		FMTP:     map[string]string{},
	}, nil
}

func parseAttributeKV(raw string) (string, string, bool) {
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}
