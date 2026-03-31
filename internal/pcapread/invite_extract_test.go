package pcapread

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFindFirstInviteWithSDPFromTransportPayload(t *testing.T) {
	dir := t.TempDir()
	invite := []byte("INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n")
	udp := buildEtherIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, invite)
	tcp := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n"))
	path := filepath.Join(dir, "invite.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), tcp, udp); err != nil {
		t.Fatal(err)
	}

	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if !strings.Contains(sdp, "v=0") {
		t.Fatalf("sdp=%q", sdp)
	}
}
