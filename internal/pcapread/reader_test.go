package pcapread

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestLoadPCAPWithLinkType(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "sample.pcap")
	t0 := time.Unix(100, 0)
	rtpPayload := append(buildRTPPayload(0x11223344, 1000, 5000), []byte{0x01, 0x02, 0x03}...)
	packetBytes := serializeUDPPacket(t, net.IPv4(192, 0, 2, 1), net.IPv4(198, 51, 100, 20), 5060, 4000, rtpPayload)

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("os.Create error = %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader error = %v", err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: t0, CaptureLength: len(packetBytes), Length: len(packetBytes)}, packetBytes); err != nil {
		t.Fatalf("WritePacket error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}

	packets, linkType, err := LoadPCAPWithLinkType(pcapPath)
	if err != nil {
		t.Fatalf("LoadPCAPWithLinkType error = %v", err)
	}
	if linkType != layers.LinkTypeEthernet {
		t.Fatalf("linkType = %v, want %v", linkType, layers.LinkTypeEthernet)
	}
	if len(packets) != 1 {
		t.Fatalf("len(packets) = %d, want 1", len(packets))
	}

	udp, ok := packets[0].TransportLayer().(*layers.UDP)
	if !ok {
		t.Fatalf("TransportLayer type = %T, want *layers.UDP", packets[0].TransportLayer())
	}
	if len(udp.Payload) != len(rtpPayload) {
		t.Fatalf("len(udp.Payload) = %d, want %d", len(udp.Payload), len(rtpPayload))
	}
}

func TestLoadPCAPMissingFileError(t *testing.T) {
	_, _, err := LoadPCAPWithLinkType("/definitely/missing/sample.pcap")
	if err == nil {
		t.Fatalf("LoadPCAPWithLinkType error = nil, want error")
	}
	if !strings.Contains(err.Error(), "cannot open pcap") {
		t.Fatalf("error %q missing cannot open pcap", err)
	}
}

func TestBuildPacketDiagnostics(t *testing.T) {
	packet := gopacket.NewPacket([]byte{0x01, 0x02, 0x03}, layers.LayerTypeEthernet, gopacket.Default)
	lines := BuildPacketDiagnostics(layers.LinkTypeEthernet, []gopacket.Packet{packet}, 1)
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], "pcap link type") {
		t.Fatalf("line[0] = %q, expected link type diagnostic", lines[0])
	}
	if !strings.Contains(lines[1], "packet #1") {
		t.Fatalf("line[1] = %q, expected packet diagnostic", lines[1])
	}
}

func serializeUDPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum error = %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers error = %v", err)
	}
	return buf.Bytes()
}

func buildRTPPayload(ssrc uint32, seq uint16, ts uint32) []byte {
	p := make([]byte, 12)
	p[0] = 0x80
	p[1] = 96
	p[2] = byte(seq >> 8)
	p[3] = byte(seq)
	p[4] = byte(ts >> 24)
	p[5] = byte(ts >> 16)
	p[6] = byte(ts >> 8)
	p[7] = byte(ts)
	p[8] = byte(ssrc >> 24)
	p[9] = byte(ssrc >> 16)
	p[10] = byte(ssrc >> 8)
	p[11] = byte(ssrc)
	return p
}
