package pcapread

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractRTPBySSRCUsesTransportLayer(t *testing.T) {
	dir := t.TempDir()
	p1 := buildEtherIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1111, 2222, append(buildRTPPayload(0x11223344, 2, 2000), 0x01))
	p2 := buildEtherIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1111, 2222, append(buildRTPPayload(0x11223344, 1, 1000), 0x02))
	non := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"))
	path := filepath.Join(dir, "rtp.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(100, 0), p1, non, p2); err != nil {
		t.Fatal(err)
	}
	packets, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}

	streams := ExtractRTPBySSRC(packets)
	pkts := streams[0x11223344]
	if len(pkts) != 2 {
		t.Fatalf("len=%d", len(pkts))
	}
	if pkts[1].CaptureTime.Before(pkts[0].CaptureTime) {
		t.Fatalf("stream not sorted by capture time")
	}
	if got := DecodableUDPCount(packets); got != 2 {
		t.Fatalf("DecodableUDPCount=%d", got)
	}
}

func TestFilterSSRC(t *testing.T) {
	streams := map[uint32][]RTPPacket{0x11223344: {{Sequence: 1, CaptureTime: time.Unix(10, 0)}, {Sequence: 2, CaptureTime: time.Unix(11, 0)}}, 0xaabbccdd: {{Sequence: 100, CaptureTime: time.Unix(10, 0)}}}
	filtered, err := FilterSSRC(streams, 0x11223344)
	if err != nil || len(filtered) != 1 || len(filtered[0x11223344]) != 2 {
		t.Fatalf("unexpected %v %#v", err, filtered)
	}
	_, err = FilterSSRC(streams, 0xdeadbeef)
	if !errors.Is(err, ErrSSRCNotFound) {
		t.Fatalf("err=%v", err)
	}
}
