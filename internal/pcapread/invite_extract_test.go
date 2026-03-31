package pcapread

import (
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
)

func TestFindFirstInviteWithSDPFromTransportPayload(t *testing.T) {
	invite := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"
	udpInvite := packetFromUDP(t, time.Unix(1, 0), []byte(invite))
	tcpNonInvite := packetFromTCP(t, time.Unix(2, 0), []byte("OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n"))

	sdp, err := FindFirstInviteWithSDP([]gopacket.Packet{tcpNonInvite, udpInvite})
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if !strings.Contains(sdp, "v=0") {
		t.Fatalf("sdp = %q, expected SDP body", sdp)
	}
}
