package app

import (
	"testing"

	"sip-tester/internal/replay"
	"sip-tester/internal/sipclient"
)

func TestDestinationFromAnswer_EarlyAndFinalSwitch(t *testing.T) {
	early, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.10",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 4000}, {Type: "video", Port: 5000}},
	}, replay.MediaStateEarly, true)
	if err != nil {
		t.Fatalf("early destination error: %v", err)
	}
	if got := early.AudioAddr.String(); got != "192.0.2.10:4000" {
		t.Fatalf("early audio addr=%s", got)
	}

	final, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.20",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 6000}, {Type: "video", Port: 7000}},
	}, replay.MediaStateFinal, true)
	if err != nil {
		t.Fatalf("final destination error: %v", err)
	}
	if got := final.AudioAddr.String(); got != "192.0.2.20:6000" {
		t.Fatalf("final audio addr=%s", got)
	}
	if got := final.VideoAddr.String(); got != "192.0.2.20:7000" {
		t.Fatalf("final video addr=%s", got)
	}
}

func TestDestinationFromAnswer_DisablesMediaPortZeroOnFinal(t *testing.T) {
	dest, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.30",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 0}, {Type: "video", Port: 7002}},
	}, replay.MediaStateFinal, true)
	if err != nil {
		t.Fatalf("destination error: %v", err)
	}
	if dest.AudioAddr != nil {
		t.Fatalf("audio should be disabled")
	}
	if got := dest.VideoAddr.String(); got != "192.0.2.30:7002" {
		t.Fatalf("video addr=%s", got)
	}
}

func TestDestinationFromAnswer_NoUsableEndpoints(t *testing.T) {
	_, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.30",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 0}, {Type: "video", Port: 0}},
	}, replay.MediaStateFinal, true)
	if err == nil {
		t.Fatalf("expected error for no usable endpoints")
	}
}
