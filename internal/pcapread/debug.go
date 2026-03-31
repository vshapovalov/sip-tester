package pcapread

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketDiagnostic struct {
	PacketNumber    int
	LayerTypes      []string
	ErrorLayer      string
	NetworkLayer    string
	TransportLayer  string
	HasNetworkLayer bool
	HasTransport    bool
}

func BuildPacketDiagnostics(linkType layers.LinkType, packets []gopacket.Packet, sampleSize int) []string {
	if sampleSize < 0 {
		sampleSize = 0
	}
	if sampleSize > len(packets) {
		sampleSize = len(packets)
	}

	out := make([]string, 0, sampleSize+1)
	out = append(out, fmt.Sprintf("pcap link type: %s", linkType))
	for i := 0; i < sampleSize; i++ {
		d := PacketDiagnosticForPacket(i+1, packets[i])
		out = append(out, d.String())
	}
	return out
}

func PacketDiagnosticForPacket(packetNumber int, packet gopacket.Packet) PacketDiagnostic {
	d := PacketDiagnostic{PacketNumber: packetNumber}
	for _, layer := range packet.Layers() {
		d.LayerTypes = append(d.LayerTypes, layer.LayerType().String())
	}
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		d.ErrorLayer = errLayer.Error()
	}
	if network := packet.NetworkLayer(); network != nil {
		d.HasNetworkLayer = true
		d.NetworkLayer = network.LayerType().String()
	}
	if transport := packet.TransportLayer(); transport != nil {
		d.HasTransport = true
		d.TransportLayer = transport.LayerType().String()
	}
	return d
}

func (d PacketDiagnostic) String() string {
	layersValue := "none"
	if len(d.LayerTypes) > 0 {
		layersValue = strings.Join(d.LayerTypes, " > ")
	}
	errorValue := "none"
	if d.ErrorLayer != "" {
		errorValue = d.ErrorLayer
	}
	networkValue := "nil"
	if d.HasNetworkLayer {
		networkValue = d.NetworkLayer
	}
	transportValue := "nil"
	if d.HasTransport {
		transportValue = d.TransportLayer
	}
	return fmt.Sprintf("packet #%d layers=[%s] error=%s network=%s transport=%s", d.PacketNumber, layersValue, errorValue, networkValue, transportValue)
}
