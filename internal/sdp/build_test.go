package sdp

import (
	"net"
	"strings"
	"testing"

	"sip-tester/internal/pcapread"
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
