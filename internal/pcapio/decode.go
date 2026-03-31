package pcapio

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86DD
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88A8
	etherTypeQinQ2 = 0x9100
	ipProtoTCP     = 6
	ipProtoUDP     = 17
)

func DecodePacket(pkt Packet) (DecodedPacket, error) {
	out := DecodedPacket{Timestamp: pkt.Timestamp, LinkType: pkt.LinkType}
	var l3 []byte
	switch pkt.LinkType {
	case LinkTypeEthernet:
		et, payload, err := parseEthernet(pkt.Data)
		if err != nil {
			return out, err
		}
		out.EtherType, l3 = et, payload
	case LinkTypeRaw:
		l3 = pkt.Data
	case LinkTypeLinuxSLL:
		et, payload, err := parseSLL(pkt.Data)
		if err != nil {
			return out, err
		}
		out.EtherType, l3 = et, payload
	case LinkTypeLinuxSLL2:
		et, payload, err := parseSLL2(pkt.Data)
		if err != nil {
			return out, err
		}
		out.EtherType, l3 = et, payload
	case LinkTypeNull:
		payload, err := parseNull(pkt.Data)
		if err != nil {
			return out, err
		}
		l3 = payload
	default:
		return out, fmt.Errorf("unsupported link type %d", pkt.LinkType)
	}
	return decodeIPAndTransport(out, l3)
}

func parseEthernet(data []byte) (uint16, []byte, error) {
	if len(data) < 14 {
		return 0, nil, fmt.Errorf("malformed ethernet header")
	}
	off := 12
	et := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	for et == etherTypeVLAN || et == etherTypeQinQ || et == etherTypeQinQ2 {
		if len(data) < off+4 {
			return 0, nil, fmt.Errorf("malformed vlan header")
		}
		et = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}
	return et, data[off:], nil
}

func parseSLL(data []byte) (uint16, []byte, error) {
	if len(data) < 16 {
		return 0, nil, fmt.Errorf("malformed linux sll header")
	}
	return binary.BigEndian.Uint16(data[14:16]), data[16:], nil
}

func parseSLL2(data []byte) (uint16, []byte, error) {
	if len(data) < 20 {
		return 0, nil, fmt.Errorf("malformed linux sll2 header")
	}
	return binary.BigEndian.Uint16(data[0:2]), data[20:], nil
}

func parseNull(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("malformed null/loopback header")
	}
	return data[4:], nil
}

func decodeIPAndTransport(out DecodedPacket, l3 []byte) (DecodedPacket, error) {
	if len(l3) < 1 {
		return out, fmt.Errorf("empty network payload")
	}
	ver := int(l3[0] >> 4)
	switch ver {
	case 4:
		return parseIPv4(out, l3)
	case 6:
		return parseIPv6(out, l3)
	default:
		if out.EtherType == etherTypeIPv4 {
			return parseIPv4(out, l3)
		}
		if out.EtherType == etherTypeIPv6 {
			return parseIPv6(out, l3)
		}
		return out, fmt.Errorf("unsupported network layer version nibble %d", ver)
	}
}

func parseIPv4(out DecodedPacket, data []byte) (DecodedPacket, error) {
	if len(data) < 20 {
		return out, fmt.Errorf("malformed ipv4 header")
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return out, fmt.Errorf("invalid ipv4 header length")
	}
	total := int(binary.BigEndian.Uint16(data[2:4]))
	if total == 0 || total > len(data) {
		total = len(data)
	}
	fragOff := binary.BigEndian.Uint16(data[6:8]) & 0x1fff
	if fragOff != 0 {
		return out, fmt.Errorf("ipv4 fragment offset unsupported")
	}
	out.IPVersion = 4
	out.Protocol = data[9]
	out.SrcIP = net.IP(append([]byte(nil), data[12:16]...))
	out.DstIP = net.IP(append([]byte(nil), data[16:20]...))
	return parseTransport(out, out.Protocol, data[ihl:total])
}

func parseIPv6(out DecodedPacket, data []byte) (DecodedPacket, error) {
	if len(data) < 40 {
		return out, fmt.Errorf("malformed ipv6 header")
	}
	out.IPVersion = 6
	out.SrcIP = net.IP(append([]byte(nil), data[8:24]...))
	out.DstIP = net.IP(append([]byte(nil), data[24:40]...))
	next := data[6]
	off := 40
	for {
		switch next {
		case 0, 43, 60:
			if len(data) < off+2 {
				return out, fmt.Errorf("malformed ipv6 extension header")
			}
			hdrLen := (int(data[off+1]) + 1) * 8
			next = data[off]
			off += hdrLen
		case 44:
			if len(data) < off+8 {
				return out, fmt.Errorf("malformed ipv6 fragment header")
			}
			if binary.BigEndian.Uint16(data[off+2:off+4])&0xfff8 != 0 {
				return out, fmt.Errorf("ipv6 fragmented packet unsupported")
			}
			next = data[off]
			off += 8
		case 51:
			if len(data) < off+2 {
				return out, fmt.Errorf("malformed ipv6 auth header")
			}
			hdrLen := (int(data[off+1]) + 2) * 4
			next = data[off]
			off += hdrLen
		default:
			if off > len(data) {
				return out, fmt.Errorf("invalid ipv6 extension chain")
			}
			out.Protocol = next
			return parseTransport(out, next, data[off:])
		}
		if off > len(data) {
			return out, fmt.Errorf("invalid ipv6 extension chain")
		}
	}
}

func parseTransport(out DecodedPacket, proto uint8, payload []byte) (DecodedPacket, error) {
	switch proto {
	case ipProtoUDP:
		if len(payload) < 8 {
			return out, fmt.Errorf("malformed udp header")
		}
		out.IsUDP = true
		out.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		out.DstPort = binary.BigEndian.Uint16(payload[2:4])
		ln := int(binary.BigEndian.Uint16(payload[4:6]))
		if ln <= 0 || ln > len(payload) {
			ln = len(payload)
		}
		out.Payload = append([]byte(nil), payload[8:ln]...)
	case ipProtoTCP:
		if len(payload) < 20 {
			return out, fmt.Errorf("malformed tcp header")
		}
		off := int(payload[12]>>4) * 4
		if off < 20 || off > len(payload) {
			return out, fmt.Errorf("invalid tcp data offset")
		}
		out.IsTCP = true
		out.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		out.DstPort = binary.BigEndian.Uint16(payload[2:4])
		out.Payload = append([]byte(nil), payload[off:]...)
	default:
		out.Payload = append([]byte(nil), payload...)
	}
	return out, nil
}
