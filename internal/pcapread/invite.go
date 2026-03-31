package pcapread

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrInviteNotFound = errors.New("sip INVITE not found")
	ErrSDPNotFound    = errors.New("sdp not found in INVITE")
)

type SDPMedia struct {
	Media        string
	PayloadTypes []int
	RTPMap       map[int]string
	FMTP         map[int]string
}

func FindFirstInviteWithSDP(packets []Packet) (string, error) {
	for _, packet := range packets {
		payload := packet.Decoded.Payload
		if len(payload) == 0 {
			continue
		}
		sdp, invite, hasBody := parseInviteSDP(payload)
		if invite && hasBody {
			return sdp, nil
		}
	}
	for _, packet := range packets {
		payload := packet.Decoded.Payload
		if len(payload) == 0 {
			continue
		}
		_, invite, _ := parseInviteSDP(payload)
		if invite {
			return "", ErrSDPNotFound
		}
	}
	return "", ErrInviteNotFound
}

func parseInviteSDP(payload []byte) (sdp string, isInvite bool, hasSDP bool) {
	text := string(payload)
	if !strings.HasPrefix(text, "INVITE ") {
		return "", false, false
	}
	parts := strings.SplitN(text, "\r\n\r\n", 2)
	if len(parts) != 2 {
		return "", true, false
	}
	headers := strings.ToLower(parts[0])
	if !strings.Contains(headers, "\ncontent-type: application/sdp") && !strings.Contains(headers, "\r\ncontent-type: application/sdp") {
		return "", true, false
	}
	body := strings.TrimSpace(parts[1])
	if body == "" {
		return "", true, false
	}
	return body, true, true
}

// unchanged below
func ParseSDPMedia(rawSDP string) ([]SDPMedia, error) {
	lines := strings.Split(rawSDP, "\n")
	media := make([]SDPMedia, 0, 2)
	var current *SDPMedia
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "m=") {
			section, ok := parseMediaLine(strings.TrimPrefix(line, "m="))
			if !ok {
				current = nil
				continue
			}
			media = append(media, section)
			current = &media[len(media)-1]
			continue
		}
		if current == nil || !strings.HasPrefix(line, "a=") {
			continue
		}
		attr := strings.TrimPrefix(line, "a=")
		if strings.HasPrefix(attr, "rtpmap:") {
			pt, val, ok := parsePTAttribute(strings.TrimPrefix(attr, "rtpmap:"))
			if ok {
				current.RTPMap[pt] = val
			}
		}
		if strings.HasPrefix(attr, "fmtp:") {
			pt, val, ok := parsePTAttribute(strings.TrimPrefix(attr, "fmtp:"))
			if ok {
				current.FMTP[pt] = val
			}
		}
	}
	if len(media) == 0 {
		return nil, fmt.Errorf("no audio/video media sections found")
	}
	return media, nil
}
func parseMediaLine(value string) (SDPMedia, bool) { /*same*/
	fields := strings.Fields(value)
	if len(fields) < 4 {
		return SDPMedia{}, false
	}
	mediaType := fields[0]
	if mediaType != "audio" && mediaType != "video" {
		return SDPMedia{}, false
	}
	section := SDPMedia{Media: mediaType, PayloadTypes: make([]int, 0, len(fields)-3), RTPMap: map[int]string{}, FMTP: map[int]string{}}
	for _, pt := range fields[3:] {
		if v, err := strconv.Atoi(pt); err == nil {
			section.PayloadTypes = append(section.PayloadTypes, v)
		}
	}
	return section, true
}
func parsePTAttribute(value string) (pt int, param string, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, "", false
	}
	idx := bytes.IndexByte([]byte(value), ' ')
	if idx <= 0 {
		return 0, "", false
	}
	parsedPT, err := strconv.Atoi(strings.TrimSpace(value[:idx]))
	if err != nil {
		return 0, "", false
	}
	return parsedPT, strings.TrimSpace(value[idx+1:]), true
}
