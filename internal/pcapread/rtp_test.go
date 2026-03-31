package pcapread

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestExtractRTPBySSRCUsesTransportLayer(t *testing.T) {
	t0 := time.Unix(100, 0)
	p1 := packetFromUDP(t, t0.Add(time.Second), append(buildRTPPayload(0x11223344, 2, 2000), 0x01))
	p2 := packetFromUDP(t, t0, append(buildRTPPayload(0x11223344, 1, 1000), 0x02))
	nonUDP := packetFromTCP(t, t0.Add(2*time.Second), []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"))

	streams := ExtractRTPBySSRC([]gopacket.Packet{p1, nonUDP, p2})
	pkts := streams[0x11223344]
	if len(pkts) != 2 {
		t.Fatalf("len(pkts) = %d, want 2", len(pkts))
	}
	if pkts[0].Sequence != 1 || pkts[1].Sequence != 2 {
		t.Fatalf("sequences = %d,%d, want sorted 1,2", pkts[0].Sequence, pkts[1].Sequence)
	}
	if got := DecodableUDPCount([]gopacket.Packet{p1, nonUDP, p2}); got != 2 {
		t.Fatalf("DecodableUDPCount = %d, want 2", got)
	}
}

func TestFilterSSRC(t *testing.T) {
	streams := map[uint32][]RTPPacket{
		0x11223344: {
			{Sequence: 1, CaptureTime: time.Unix(10, 0)},
			{Sequence: 2, CaptureTime: time.Unix(11, 0)},
		},
		0xaabbccdd: {
			{Sequence: 100, CaptureTime: time.Unix(10, 0)},
		},
	}

	filtered, err := FilterSSRC(streams, 0x11223344)
	if err != nil {
		t.Fatalf("FilterSSRC returned error: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("len(filtered) = %d, want 1", len(filtered))
	}
	if len(filtered[0x11223344]) != 2 {
		t.Fatalf("len(filtered[0x11223344]) = %d, want 2", len(filtered[0x11223344]))
	}

	_, err = FilterSSRC(streams, 0xdeadbeef)
	if !errors.Is(err, ErrSSRCNotFound) {
		t.Fatalf("FilterSSRC missing SSRC error = %v, want ErrSSRCNotFound", err)
	}
}

func packetFromUDP(t *testing.T, ts time.Time, payload []byte) gopacket.Packet {
	t.Helper()
	b := serializeUDPPacket(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1111, 2222, payload)
	pkt := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo.Timestamp = ts
	return pkt
}

func packetFromTCP(t *testing.T, ts time.Time, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, SYN: true, Window: 8192}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum error = %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers error = %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo.Timestamp = ts
	return pkt
}
