package sdp

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"sip-tester/internal/pcapread"
	"sip-tester/internal/sipclient"
)

var staticAudioRTPMap = map[int]string{
	0: "PCMU/8000",
	8: "PCMA/8000",
}

type PayloadTypeNegotiation struct {
	MediaType    string
	Codec        string
	LocalPT      uint8
	NegotiatedPT uint8
}

type NegotiatedMedia struct {
	PayloadTypeMappings []PayloadTypeNegotiation
}

// BuildOffer builds a fresh SDP offer using parsed media metadata and a caller-provided local IP.
// It intentionally does not preserve original transport addresses, ICE attributes, or crypto lines.
func BuildOffer(localIP net.IP, audioPort, videoPort int, media []pcapread.SDPMedia) (string, error) {
	if localIP == nil {
		return "", fmt.Errorf("local IP is required")
	}
	if audioPort <= 0 || videoPort <= 0 {
		return "", fmt.Errorf("audio/video ports must be greater than zero")
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
		port := audioPort
		if m.Media == "video" {
			port = videoPort
		}
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

// BuildAnswer builds an SDP answer for inbound mode by intersecting the remote offer with local capabilities.
func BuildAnswer(localIP net.IP, audioPort, videoPort int, localMedia []pcapread.SDPMedia, remoteOffer sipclient.SDPAnswer) (string, NegotiatedMedia, error) {
	if localIP == nil {
		return "", NegotiatedMedia{}, fmt.Errorf("local IP is required")
	}
	if audioPort <= 0 || videoPort <= 0 {
		return "", NegotiatedMedia{}, fmt.Errorf("audio/video ports must be greater than zero")
	}
	if len(localMedia) == 0 {
		return "", NegotiatedMedia{}, fmt.Errorf("at least one local media section is required")
	}
	if len(remoteOffer.Media) == 0 {
		return "", NegotiatedMedia{}, fmt.Errorf("remote SDP offer has no media sections")
	}

	ipFamily := "IP4"
	if localIP.To4() == nil {
		ipFamily = "IP6"
	}

	localCaps := buildLocalCapabilities(localMedia)

	lines := []string{
		"v=0",
		fmt.Sprintf("o=- 0 0 IN %s %s", ipFamily, localIP.String()),
		"s=-",
		fmt.Sprintf("c=IN %s %s", ipFamily, localIP.String()),
		"t=0 0",
	}

	negotiated := NegotiatedMedia{PayloadTypeMappings: make([]PayloadTypeNegotiation, 0, 6)}

	for _, offeredMedia := range remoteOffer.Media {
		proto := offeredMedia.Protocol
		if strings.TrimSpace(proto) == "" {
			proto = "RTP/AVP"
		}

		port := 0
		switch offeredMedia.Type {
		case "audio":
			if _, ok := localCaps["audio"]; ok {
				port = audioPort
			}
		case "video":
			if _, ok := localCaps["video"]; ok {
				port = videoPort
			}
		default:
			port = 0
		}

		accepted := make([]acceptedFormat, 0, len(offeredMedia.Formats))
		if port != 0 {
			for _, f := range offeredMedia.Formats {
				offerPT, err := strconv.Atoi(strings.TrimSpace(f))
				if err != nil {
					continue
				}
				offerCodec := codecForPayload(offeredMedia.Type, offerPT, offeredMedia.RTPMap)
				if offerCodec == "" {
					continue
				}
				local, ok := localCaps[offeredMedia.Type][offerCodec]
				if !ok {
					continue
				}
				accepted = append(accepted, acceptedFormat{
					offerPT:   offerPT,
					codec:     offerCodec,
					rtpMap:    offeredMedia.RTPMap[f],
					fmtp:      offeredMedia.FMTP[f],
					localPT:   local.pt,
					mediaType: offeredMedia.Type,
				})
				negotiated.PayloadTypeMappings = append(negotiated.PayloadTypeMappings, PayloadTypeNegotiation{
					MediaType:    offeredMedia.Type,
					Codec:        offerCodec,
					LocalPT:      uint8(local.pt),
					NegotiatedPT: uint8(offerPT),
				})
			}
		}

		if len(accepted) == 0 {
			rejectedFormats := offeredMedia.Formats
			if len(rejectedFormats) == 0 {
				rejectedFormats = []string{"0"}
			}
			lines = append(lines, fmt.Sprintf("m=%s 0 %s %s", offeredMedia.Type, proto, strings.Join(rejectedFormats, " ")))
			continue
		}

		formatValues := make([]string, 0, len(accepted))
		for _, f := range accepted {
			formatValues = append(formatValues, strconv.Itoa(f.offerPT))
		}
		lines = append(lines, fmt.Sprintf("m=%s %d %s %s", offeredMedia.Type, port, proto, strings.Join(formatValues, " ")))

		for _, f := range accepted {
			if f.rtpMap != "" {
				lines = append(lines, fmt.Sprintf("a=rtpmap:%d %s", f.offerPT, f.rtpMap))
			}
			if f.fmtp != "" {
				lines = append(lines, fmt.Sprintf("a=fmtp:%d %s", f.offerPT, f.fmtp))
			}
		}
	}

	return strings.Join(lines, "\r\n") + "\r\n", negotiated, nil
}

type localCapability struct {
	pt int
}

type acceptedFormat struct {
	offerPT   int
	codec     string
	rtpMap    string
	fmtp      string
	localPT   int
	mediaType string
}

func buildLocalCapabilities(localMedia []pcapread.SDPMedia) map[string]map[string]localCapability {
	caps := map[string]map[string]localCapability{}
	for _, section := range localMedia {
		if section.Media != "audio" && section.Media != "video" {
			continue
		}
		if _, ok := caps[section.Media]; !ok {
			caps[section.Media] = map[string]localCapability{}
		}
		for _, pt := range section.PayloadTypes {
			codec := codecForPayloadInt(section.Media, pt, section.RTPMap)
			if codec == "" {
				continue
			}
			if _, exists := caps[section.Media][codec]; !exists {
				caps[section.Media][codec] = localCapability{pt: pt}
			}
		}
	}
	return caps
}

func codecForPayload(mediaType string, pt int, rtpmap map[string]string) string {
	if v, ok := rtpmap[strconv.Itoa(pt)]; ok {
		return canonicalCodec(v)
	}
	if mediaType == "audio" {
		if v, ok := staticAudioRTPMap[pt]; ok {
			return canonicalCodec(v)
		}
	}
	return ""
}

func codecForPayloadInt(mediaType string, pt int, rtpmap map[int]string) string {
	if v, ok := rtpmap[pt]; ok {
		return canonicalCodec(v)
	}
	if mediaType == "audio" {
		if v, ok := staticAudioRTPMap[pt]; ok {
			return canonicalCodec(v)
		}
	}
	return ""
}

func canonicalCodec(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	parts := strings.Split(v, "/")
	parts[0] = strings.ToUpper(parts[0])
	return strings.Join(parts, "/")
}
