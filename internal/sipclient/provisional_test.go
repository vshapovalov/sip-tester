package sipclient

import (
	"strings"
	"testing"
)

func TestParseSDPAnswer_ParsesMediaLevelConnectionFor183(t *testing.T) {
	raw := strings.Join([]string{
		"v=0",
		"o=- 1 1 IN IP4 192.0.2.10",
		"s=-",
		"c=IN IP4 192.0.2.10",
		"t=0 0",
		"m=audio 4000 RTP/AVP 0",
		"c=IN IP4 198.51.100.20",
		"m=video 5000 RTP/AVP 96",
	}, "\r\n")

	answer, err := ParseSDPAnswer(raw)
	if err != nil {
		t.Fatalf("ParseSDPAnswer() error = %v", err)
	}
	if got, want := answer.ConnectionIP, "192.0.2.10"; got != want {
		t.Fatalf("connection ip=%q want=%q", got, want)
	}
	if got, want := answer.Media[0].ConnectionIP, "198.51.100.20"; got != want {
		t.Fatalf("audio connection ip=%q want=%q", got, want)
	}
	if got, want := answer.Media[1].ConnectionIP, ""; got != want {
		t.Fatalf("video connection ip=%q want empty", got)
	}
}

func TestRequire100Rel(t *testing.T) {
	if !require100Rel("timer, 100rel") {
		t.Fatalf("expected 100rel to be detected")
	}
	if require100Rel("timer") {
		t.Fatalf("did not expect 100rel")
	}
}
