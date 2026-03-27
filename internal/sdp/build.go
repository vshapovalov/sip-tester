package sdp

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"sip-tester/internal/pcapread"
)

const (
	defaultAudioPort = 4000
	defaultVideoPort = 4002
)

// BuildOffer builds a fresh SDP offer using parsed media metadata and a caller-provided local IP.
// It intentionally does not preserve original transport addresses, ICE attributes, or crypto lines.
func BuildOffer(localIP net.IP, media []pcapread.SDPMedia) (string, error) {
	if localIP == nil {
		return "", fmt.Errorf("local IP is required")
	}
	if len(media) == 0 {
		return "", fmt.Errorf("at least one media section is required")
	}

	ipFamily := "IP4"
	if localIP.To4() == nil {
		ipFamily = "IP6"
	}

	sections := make([]pcapread.SDPMedia, 0, 2)
	for _, m := range media {
		if m.Media == "audio" || m.Media == "video" {
			sections = append(sections, m)
		}
	}
	if len(sections) == 0 {
		return "", fmt.Errorf("no audio/video media sections provided")
	}

	lines := []string{
		"v=0",
		fmt.Sprintf("o=- 0 0 IN %s %s", ipFamily, localIP.String()),
		"s=-",
		fmt.Sprintf("c=IN %s %s", ipFamily, localIP.String()),
		"t=0 0",
	}

	for _, m := range sections {
		port := mediaPort(m.Media)
		pts := append([]int(nil), m.PayloadTypes...)
		sort.Ints(pts)

		payloadStrings := make([]string, 0, len(pts))
		for _, pt := range pts {
			payloadStrings = append(payloadStrings, strconv.Itoa(pt))
		}
		if len(payloadStrings) == 0 {
			return "", fmt.Errorf("%s media has no payload types", m.Media)
		}

		lines = append(lines, fmt.Sprintf("m=%s %d RTP/AVP %s", m.Media, port, strings.Join(payloadStrings, " ")))

		for _, pt := range pts {
			if v, ok := m.RTPMap[pt]; ok {
				lines = append(lines, fmt.Sprintf("a=rtpmap:%d %s", pt, v))
			}
			if v, ok := m.FMTP[pt]; ok {
				lines = append(lines, fmt.Sprintf("a=fmtp:%d %s", pt, v))
			}
		}
	}

	return strings.Join(lines, "\r\n") + "\r\n", nil
}

func mediaPort(kind string) int {
	if kind == "video" {
		return defaultVideoPort
	}
	return defaultAudioPort
}
