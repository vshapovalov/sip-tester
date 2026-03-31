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
	foundInvite := false
	for i, packet := range packets {
		payload := packet.Decoded.Payload
		if len(payload) == 0 {
			continue
		}
		if !payloadStartsInvite(payload) {
			continue
		}
		foundInvite = true

		assembled, err := assembleSIPMessageFromPacket(i, packets)
		if err != nil {
			continue
		}
		sdp, invite, hasSDP := parseInviteSDP(assembled)
		if invite && hasSDP {
			return sdp, nil
		}
	}
	if foundInvite {
		return "", ErrSDPNotFound
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

type sipMessageFraming struct {
	HeaderComplete bool
	HeaderLength   int
	ContentLength  int
	TotalLength    int
}

//type packetFlowKey struct {
//	Protocol uint8
//	SrcIP    string
//	DstIP    string
//	SrcPort  uint16
//	DstPort  uint16
//}

func assembleSIPMessageFromPacket(startIdx int, packets []Packet) ([]byte, error) {
	if startIdx < 0 || startIdx >= len(packets) {
		return nil, fmt.Errorf("invalid packet index %d", startIdx)
	}
	start := packets[startIdx]
	//startFlow, ok := flowKeyFromPacket(start)
	//if !ok {
	//	return nil, fmt.Errorf("missing transport flow for packet index %d", startIdx)
	//}
	assembled := append([]byte{}, start.Decoded.Payload...)

	for i := startIdx; i < len(packets); i++ {
		if i > startIdx {
			//nextFlow, ok := flowKeyFromPacket(packets[i])
			//if !ok || nextFlow != startFlow {
			//	continue
			//}
			assembled = append(assembled, packets[i].Raw.Data...)
		}

		framing, err := parseSIPMessageFraming(assembled)
		if err != nil {
			return nil, err
		}
		if !framing.HeaderComplete {
			continue
		}
		if len(assembled) < framing.TotalLength {
			continue
		}
		return assembled[:framing.TotalLength], nil
	}
	return nil, fmt.Errorf("incomplete SIP INVITE message while assembling from packet index %d", startIdx)
}

func parseSIPMessageFraming(payload []byte) (sipMessageFraming, error) {
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return sipMessageFraming{HeaderComplete: false}, nil
	}
	headerLen := headerEnd + 4
	headerText := string(payload[:headerEnd])
	contentLen, err := parseContentLength(headerText)
	if err != nil {
		return sipMessageFraming{}, err
	}
	return sipMessageFraming{
		HeaderComplete: true,
		HeaderLength:   headerLen,
		ContentLength:  contentLen,
		TotalLength:    headerLen + contentLen,
	}, nil
}

func parseContentLength(headers string) (int, error) {
	for _, line := range strings.Split(headers, "\r\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			continue
		}
		value := strings.TrimSpace(parts[1])
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid Content-Length %q", value)
		}
		return n, nil
	}
	return 0, fmt.Errorf("missing Content-Length header")
}

//func flowKeyFromPacket(packet Packet) (packetFlowKey, bool) {
//	if packet.DecodeErr != nil {
//		return packetFlowKey{}, false
//	}
//	if !packet.Decoded.IsTCP && !packet.Decoded.IsUDP {
//		return packetFlowKey{}, false
//	}
//	if len(packet.Decoded.SrcIP) == 0 || len(packet.Decoded.DstIP) == 0 {
//		return packetFlowKey{}, false
//	}
//	return packetFlowKey{
//		Protocol: packet.Decoded.Protocol,
//		SrcIP:    ipString(packet.Decoded.SrcIP),
//		DstIP:    ipString(packet.Decoded.DstIP),
//		SrcPort:  packet.Decoded.SrcPort,
//		DstPort:  packet.Decoded.DstPort,
//	}, true
//}

func payloadStartsInvite(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("INVITE "))
}

//func ipString(ip net.IP) string {
//	if ip4 := ip.To4(); ip4 != nil {
//		return ip4.String()
//	}
//	return ip.String()
//}

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
