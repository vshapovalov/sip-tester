package pcapread

import "testing"

func TestParseSDPMedia(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=- 1 1 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0 96\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:96 opus/48000/2\r\n" +
		"a=fmtp:96 useinbandfec=1\r\n" +
		"m=video 51372 RTP/AVP 97\r\n" +
		"a=rtpmap:97 H264/90000\r\n" +
		"a=fmtp:97 profile-level-id=42e01f;packetization-mode=1\r\n"

	media, err := ParseSDPMedia(sdp)
	if err != nil {
		t.Fatalf("ParseSDPMedia returned error: %v", err)
	}
	if len(media) != 2 {
		t.Fatalf("len(media) = %d, want 2", len(media))
	}

	if media[0].Media != "audio" {
		t.Fatalf("media[0].Media = %q, want audio", media[0].Media)
	}
	if len(media[0].PayloadTypes) != 2 || media[0].PayloadTypes[0] != 0 || media[0].PayloadTypes[1] != 96 {
		t.Fatalf("unexpected audio payload types: %#v", media[0].PayloadTypes)
	}
	if media[0].RTPMap[96] != "opus/48000/2" {
		t.Fatalf("audio rtpmap 96 = %q", media[0].RTPMap[96])
	}
	if media[0].FMTP[96] != "useinbandfec=1" {
		t.Fatalf("audio fmtp 96 = %q", media[0].FMTP[96])
	}

	if media[1].Media != "video" {
		t.Fatalf("media[1].Media = %q, want video", media[1].Media)
	}
	if media[1].RTPMap[97] != "H264/90000" {
		t.Fatalf("video rtpmap 97 = %q", media[1].RTPMap[97])
	}
}
