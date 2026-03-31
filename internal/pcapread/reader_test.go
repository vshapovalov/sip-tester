package pcapread

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPCAPWithLinkType(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "sample.pcap")
	rtpPayload := append(buildRTPPayload(0x11223344, 1000, 5000), []byte{1, 2, 3}...)
	frame := buildEtherIPv4UDP(net.IPv4(192, 0, 2, 1), net.IPv4(198, 51, 100, 20), 5060, 4000, rtpPayload)
	if err := writeClassicPCAP(pcapPath, 1, time.Unix(100, 0), frame); err != nil {
		t.Fatal(err)
	}

	packets, linkType, err := LoadPCAPWithLinkType(pcapPath)
	if err != nil {
		t.Fatalf("LoadPCAPWithLinkType error = %v", err)
	}
	if linkType != 1 {
		t.Fatalf("linkType = %v, want 1", linkType)
	}
	if len(packets) != 1 {
		t.Fatalf("len(packets) = %d, want 1", len(packets))
	}
	if packets[0].DecodeErr != nil {
		t.Fatalf("DecodeErr = %v", packets[0].DecodeErr)
	}
	if !packets[0].Decoded.IsUDP {
		t.Fatalf("IsUDP=false")
	}
	if len(packets[0].Decoded.Payload) != len(rtpPayload) {
		t.Fatalf("len payload=%d", len(packets[0].Decoded.Payload))
	}
}

func TestLoadPCAPMissingFileError(t *testing.T) {
	_, _, err := LoadPCAPWithLinkType("/definitely/missing/sample.pcap")
	if err == nil {
		t.Fatalf("want error")
	}
	if !strings.Contains(err.Error(), "cannot open pcap") {
		t.Fatalf("error %q", err)
	}
}

func TestBuildPacketDiagnostics(t *testing.T) {
	pkt := Packet{DecodeErr: nil}
	lines := BuildPacketDiagnostics(1, []Packet{pkt}, 1)
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], "pcap link type") {
		t.Fatalf("line0=%q", lines[0])
	}
	if !strings.Contains(lines[1], "packet #1") {
		t.Fatalf("line1=%q", lines[1])
	}
}
