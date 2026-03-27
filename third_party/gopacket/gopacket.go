package gopacket

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/google/gopacket/layers"
)

type CaptureInfo struct {
	Timestamp time.Time
}

type PacketMetadata struct {
	CaptureInfo CaptureInfo
}

type Layer interface{}

type ApplicationLayer interface {
	Payload() []byte
}

type Packet interface {
	Layer(t layers.LayerType) Layer
	ApplicationLayer() ApplicationLayer
	Metadata() *PacketMetadata
}

type packetDataSource interface {
	ReadPacketData() (data []byte, ci CaptureInfo, err error)
}

type PacketSource struct {
	src      packetDataSource
	linkType layers.LinkType
}

func NewPacketSource(src packetDataSource, linkType layers.LinkType) *PacketSource {
	return &PacketSource{src: src, linkType: linkType}
}

func (p *PacketSource) NextPacket() (Packet, error) {
	data, ci, err := p.src.ReadPacketData()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	return decodePacket(data, ci, p.linkType), nil
}

type payloadLayer struct{ data []byte }

func (p payloadLayer) Payload() []byte { return p.data }

type decodedPacket struct {
	meta *PacketMetadata
	udp  *layers.UDP
	tcp  *layers.TCP
	app  payloadLayer
}

func (d *decodedPacket) Layer(t layers.LayerType) Layer {
	switch t {
	case layers.LayerTypeUDP:
		if d.udp != nil {
			return d.udp
		}
	case layers.LayerTypeTCP:
		if d.tcp != nil {
			return d.tcp
		}
	}
	return nil
}

func (d *decodedPacket) ApplicationLayer() ApplicationLayer {
	if len(d.app.data) == 0 {
		return nil
	}
	return d.app
}

func (d *decodedPacket) Metadata() *PacketMetadata { return d.meta }

func decodePacket(data []byte, ci CaptureInfo, linkType layers.LinkType) Packet {
	payload := data
	if linkType == layers.LinkTypeEthernet {
		if len(payload) < 14 {
			return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: payload}}
		}
		ethType := binary.BigEndian.Uint16(payload[12:14])
		payload = payload[14:]
		switch ethType {
		case 0x0800:
			return decodeIPv4(payload, ci)
		case 0x86DD:
			return decodeIPv6(payload, ci)
		default:
			return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: payload}}
		}
	}

	if linkType == layers.LinkTypeRaw {
		if len(payload) > 0 {
			version := payload[0] >> 4
			if version == 4 {
				return decodeIPv4(payload, ci)
			}
			if version == 6 {
				return decodeIPv6(payload, ci)
			}
		}
	}

	return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: payload}}
}

func decodeIPv4(data []byte, ci CaptureInfo) Packet {
	if len(data) < 20 {
		return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: data}}
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: data}}
	}
	proto := data[9]
	return decodeL4(proto, data[ihl:], ci)
}

func decodeIPv6(data []byte, ci CaptureInfo) Packet {
	if len(data) < 40 {
		return &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}, app: payloadLayer{data: data}}
	}
	next := data[6]
	return decodeL4(next, data[40:], ci)
}

func decodeL4(proto byte, data []byte, ci CaptureInfo) Packet {
	pkt := &decodedPacket{meta: &PacketMetadata{CaptureInfo: ci}}
	switch proto {
	case 17:
		if len(data) < 8 {
			pkt.app = payloadLayer{data: data}
			return pkt
		}
		pkt.udp = &layers.UDP{Payload: append([]byte(nil), data[8:]...)}
		pkt.app = payloadLayer{data: pkt.udp.Payload}
		return pkt
	case 6:
		if len(data) < 20 {
			pkt.app = payloadLayer{data: data}
			return pkt
		}
		offset := int(data[12]>>4) * 4
		if offset < 20 || len(data) < offset {
			offset = 20
			if len(data) < offset {
				offset = len(data)
			}
		}
		pkt.tcp = &layers.TCP{Payload: append([]byte(nil), data[offset:]...)}
		pkt.app = payloadLayer{data: pkt.tcp.Payload}
		return pkt
	default:
		pkt.app = payloadLayer{data: data}
		return pkt
	}
}
