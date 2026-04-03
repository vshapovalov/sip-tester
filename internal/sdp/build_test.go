package sdp

import (
	"net"
	"strings"
	"testing"

	"sip-tester/internal/pcapread"
	"sip-tester/internal/sipclient"
)

func TestBuildOfferAudioOnly(t *testing.T) {
	offer, err := BuildOffer(net.ParseIP("192.0.2.10"), 12000, 12002, []pcapread.SDPMedia{
		{
			Media:        "audio",
			PayloadTypes: []int{111, 0},
			RTPMap: map[int]string{
				111: "opus/48000/2",
				0:   "PCMU/8000",
			},
			FMTP: map[int]string{111: "minptime=10;useinbandfec=1"},
		},
	})
	if err != nil {
		t.Fatalf("BuildOffer returned error: %v", err)
	}

	mustContain(t, offer, "v=0\r\n")
	mustContain(t, offer, "o=- 0 0 IN IP4 192.0.2.10\r\n")
	mustContain(t, offer, "c=IN IP4 192.0.2.10\r\n")
	mustContain(t, offer, "m=audio 12000 RTP/AVP 0 111\r\n")
	mustContain(t, offer, "a=rtpmap:0 PCMU/8000\r\n")
	mustContain(t, offer, "a=rtpmap:111 opus/48000/2\r\n")
	mustContain(t, offer, "a=fmtp:111 minptime=10;useinbandfec=1\r\n")
	mustNotContain(t, offer, "a=candidate:")
	mustNotContain(t, offer, "a=crypto:")
}

func TestBuildOfferVideoOnlyIPv6(t *testing.T) {
	offer, err := BuildOffer(net.ParseIP("2001:db8::1234"), 13000, 13002, []pcapread.SDPMedia{
		{
			Media:        "video",
			PayloadTypes: []int{96},
			RTPMap:       map[int]string{96: "H264/90000"},
			FMTP:         map[int]string{96: "profile-level-id=42e01f;packetization-mode=1"},
		},
	})
	if err != nil {
		t.Fatalf("BuildOffer returned error: %v", err)
	}

	mustContain(t, offer, "o=- 0 0 IN IP6 2001:db8::1234\r\n")
	mustContain(t, offer, "c=IN IP6 2001:db8::1234\r\n")
	mustContain(t, offer, "m=video 13002 RTP/AVP 96\r\n")
}

func TestBuildOfferAudioAndVideo(t *testing.T) {
	offer, err := BuildOffer(net.ParseIP("198.51.100.44"), 14000, 14002, []pcapread.SDPMedia{
		{Media: "audio", PayloadTypes: []int{8}, RTPMap: map[int]string{8: "PCMA/8000"}, FMTP: map[int]string{}},
		{Media: "video", PayloadTypes: []int{102}, RTPMap: map[int]string{102: "H264/90000"}, FMTP: map[int]string{}},
	})
	if err != nil {
		t.Fatalf("BuildOffer returned error: %v", err)
	}

	audioIdx := strings.Index(offer, "m=audio 14000 RTP/AVP 8\r\n")
	videoIdx := strings.Index(offer, "m=video 14002 RTP/AVP 102\r\n")
	if audioIdx == -1 || videoIdx == -1 {
		t.Fatalf("missing media lines in offer: %q", offer)
	}
	if audioIdx > videoIdx {
		t.Fatalf("expected audio media to appear before video media")
	}
}

func TestBuildOfferRejectsEmptyMedia(t *testing.T) {
	_, err := BuildOffer(net.ParseIP("192.0.2.10"), 12000, 12002, nil)
	if err == nil {
		t.Fatalf("expected error for empty media")
	}
}

func TestBuildOfferRejectsZeroPort(t *testing.T) {
	_, err := BuildOffer(net.ParseIP("192.0.2.10"), 0, 12002, []pcapread.SDPMedia{{Media: "audio", PayloadTypes: []int{0}}})
	if err == nil {
		t.Fatalf("expected error for zero port")
	}
}

func TestBuildAnswer_UsesOfferedDynamicPayloadTypeForH264(t *testing.T) {
	answer, negotiated, err := BuildAnswer(net.ParseIP("157.180.116.6"), 10496, 12748, []pcapread.SDPMedia{
		{Media: "audio", PayloadTypes: []int{0, 8, 101}, RTPMap: map[int]string{101: "telephone-event/8000"}, FMTP: map[int]string{101: "0-16"}},
		{Media: "video", PayloadTypes: []int{96}, RTPMap: map[int]string{96: "H264/90000"}, FMTP: map[int]string{96: "profile-level-id=42801F"}},
	}, sipclient.SDPAnswer{
		Media: []sipclient.SDPMedia{
			{Type: "audio", Port: 18704, Protocol: "RTP/AVP", Formats: []string{"0", "8", "101"}, RTPMap: map[string]string{"0": "PCMU/8000", "8": "PCMA/8000", "101": "telephone-event/8000"}, FMTP: map[string]string{"101": "0-16"}},
			{Type: "video", Port: 12254, Protocol: "RTP/AVP", Formats: []string{"99"}, RTPMap: map[string]string{"99": "H264/90000"}, FMTP: map[string]string{"99": "profile-level-id=42801F"}},
		},
	})
	if err != nil {
		t.Fatalf("BuildAnswer error: %v", err)
	}
	mustContain(t, answer, "m=video 12748 RTP/AVP 99\r\n")
	mustNotContain(t, answer, "m=video 12748 RTP/AVP 96\r\n")
	mustContain(t, answer, "a=fmtp:99 profile-level-id=42801F\r\n")

	if !hasNegotiatedMapping(negotiated, "video", 96, 99) {
		t.Fatalf("expected negotiated mapping video 96->99, got %#v", negotiated.PayloadTypeMappings)
	}
}

func TestBuildAnswer_OfferDrivesMediaOrderAndUnsupportedSections(t *testing.T) {
	answer, _, err := BuildAnswer(net.ParseIP("192.0.2.10"), 30000, 30002, []pcapread.SDPMedia{
		{Media: "audio", PayloadTypes: []int{0}, RTPMap: map[int]string{}, FMTP: map[int]string{}},
	}, sipclient.SDPAnswer{
		Media: []sipclient.SDPMedia{
			{Type: "video", Port: 4000, Protocol: "RTP/AVP", Formats: []string{"99"}, RTPMap: map[string]string{"99": "H264/90000"}, FMTP: map[string]string{"99": "profile-level-id=42801F"}},
			{Type: "audio", Port: 5000, Protocol: "RTP/AVP", Formats: []string{"0"}, RTPMap: map[string]string{"0": "PCMU/8000"}, FMTP: map[string]string{}},
			{Type: "application", Port: 6000, Protocol: "UDP", Formats: []string{"webrtc-datachannel"}, RTPMap: map[string]string{}, FMTP: map[string]string{}},
		},
	})
	if err != nil {
		t.Fatalf("BuildAnswer error: %v", err)
	}
	videoIdx := strings.Index(answer, "m=video 0 RTP/AVP 99\r\n")
	audioIdx := strings.Index(answer, "m=audio 30000 RTP/AVP 0\r\n")
	appIdx := strings.Index(answer, "m=application 0 UDP webrtc-datachannel\r\n")
	if videoIdx == -1 || audioIdx == -1 || appIdx == -1 {
		t.Fatalf("missing expected media lines in answer: %q", answer)
	}
	if !(videoIdx < audioIdx && audioIdx < appIdx) {
		t.Fatalf("answer media order does not follow offer order: %q", answer)
	}
}

func TestBuildAnswer_TelephoneEventOnlyWhenOffered(t *testing.T) {
	answer, _, err := BuildAnswer(net.ParseIP("192.0.2.11"), 31000, 31002, []pcapread.SDPMedia{
		{Media: "audio", PayloadTypes: []int{0, 101}, RTPMap: map[int]string{101: "telephone-event/8000"}, FMTP: map[int]string{101: "0-16"}},
	}, sipclient.SDPAnswer{
		Media: []sipclient.SDPMedia{
			{Type: "audio", Port: 5000, Protocol: "RTP/AVP", Formats: []string{"0"}, RTPMap: map[string]string{"0": "PCMU/8000"}, FMTP: map[string]string{}},
		},
	})
	if err != nil {
		t.Fatalf("BuildAnswer error: %v", err)
	}
	mustNotContain(t, answer, "telephone-event")
}

func hasNegotiatedMapping(negotiated NegotiatedMedia, media string, localPT, negotiatedPT uint8) bool {
	for _, m := range negotiated.PayloadTypeMappings {
		if m.MediaType == media && m.LocalPT == localPT && m.NegotiatedPT == negotiatedPT {
			return true
		}
	}
	return false
}

func mustContain(t *testing.T, s, want string) {
	t.Helper()
	if !strings.Contains(s, want) {
		t.Fatalf("expected %q to contain %q", s, want)
	}
}

func mustNotContain(t *testing.T, s, unwanted string) {
	t.Helper()
	if strings.Contains(s, unwanted) {
		t.Fatalf("expected %q not to contain %q", s, unwanted)
	}
}
