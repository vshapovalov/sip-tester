package pcapio

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadPCAPHeaderAndRecord(t *testing.T) {
	var b bytes.Buffer
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], LinkTypeRaw)
	b.Write(gh)
	payload := []byte{0x45, 0, 0, 20}
	rh := make([]byte, 16)
	binary.LittleEndian.PutUint32(rh[0:4], 10)
	binary.LittleEndian.PutUint32(rh[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(rh[12:16], uint32(len(payload)))
	b.Write(rh)
	b.Write(payload)

	pkts, info, err := readPCAP(bytes.NewReader(b.Bytes()))
	if err != nil || info.Format != FormatPCAP || len(pkts) != 1 {
		t.Fatalf("err=%v info=%+v len=%d", err, info, len(pkts))
	}
}

func TestReadPCAPNGInterfaceAndEPB(t *testing.T) {
	p := buildMinimalPCAPNG(LinkTypeEthernet, []byte{1, 2, 3, 4})
	pkts, info, err := readPCAPNG(bytes.NewReader(p))
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != FormatPCAPNG || len(pkts) != 1 || pkts[0].LinkType != LinkTypeEthernet {
		t.Fatalf("bad %+v %+v", info, pkts)
	}
}

func TestDecodeEthernetVLANUDP(t *testing.T) {
	data := append([]byte{0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0x81, 0x00, 0, 1, 0x08, 0x00}, buildIPv4UDP()...)
	d, err := DecodePacket(Packet{Data: data, LinkType: LinkTypeEthernet})
	if err != nil || !d.IsUDP {
		t.Fatalf("err=%v d=%+v", err, d)
	}
}

func TestDecodeRawIP(t *testing.T) {
	d, err := DecodePacket(Packet{Data: buildIPv4UDP(), LinkType: LinkTypeRaw})
	if err != nil || d.IPVersion != 4 {
		t.Fatalf("err=%v d=%+v", err, d)
	}
}

func TestDecodeLinuxSLL(t *testing.T) {
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[14:16], etherTypeIPv4)
	d, err := DecodePacket(Packet{Data: append(h, buildIPv4UDP()...), LinkType: LinkTypeLinuxSLL})
	if err != nil || !d.IsUDP {
		t.Fatalf("err=%v", err)
	}
}

func TestDecodeIPv6ExtensionToUDP(t *testing.T) {
	ip := make([]byte, 48)
	ip[0] = 0x60
	ip[6] = 0 // hop-by-hop
	ip[7] = 64
	ip[4], ip[5] = 0, 8
	ip[40] = 17 // next=udp
	ip[41] = 0  // len=8
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 1)
	binary.BigEndian.PutUint16(udp[2:4], 2)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	d, err := DecodePacket(Packet{Data: append(ip, udp...), LinkType: LinkTypeRaw})
	if err != nil || !d.IsUDP || d.IPVersion != 6 {
		t.Fatalf("err=%v d=%+v", err, d)
	}
}

func TestDecodeTCP(t *testing.T) {
	ip := buildIPv4TCP([]byte{1, 2, 3})
	d, err := DecodePacket(Packet{Data: ip, LinkType: LinkTypeRaw})
	if err != nil || !d.IsTCP || len(d.Payload) != 3 {
		t.Fatalf("err=%v d=%+v", err, d)
	}
}

func TestReadAllDetectsFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.pcapng")
	if err := os.WriteFile(path, buildMinimalPCAPNG(LinkTypeRaw, []byte{0x60}), 0o644); err != nil {
		t.Fatal(err)
	}
	pkts, info, err := ReadAll(path)
	if err != nil || info.Format != FormatPCAPNG || len(pkts) != 1 {
		t.Fatalf("err=%v info=%+v", err, info)
	}
}

func buildIPv4UDP() []byte {
	ip := make([]byte, 28)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 17
	copy(ip[12:16], []byte{1, 1, 1, 1})
	copy(ip[16:20], []byte{2, 2, 2, 2})
	binary.BigEndian.PutUint16(ip[20:22], 1111)
	binary.BigEndian.PutUint16(ip[22:24], 2222)
	binary.BigEndian.PutUint16(ip[24:26], 8)
	return ip
}

func buildIPv4TCP(payload []byte) []byte {
	ip := make([]byte, 20+20+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 6
	copy(ip[12:16], []byte{1, 1, 1, 1})
	copy(ip[16:20], []byte{2, 2, 2, 2})
	binary.BigEndian.PutUint16(ip[20:22], 1000)
	binary.BigEndian.PutUint16(ip[22:24], 2000)
	ip[32] = 0x50
	copy(ip[40:], payload)
	return ip
}

func buildMinimalPCAPNG(linkType uint32, payload []byte) []byte {
	var out bytes.Buffer
	wblock := func(t uint32, body []byte) {
		l := uint32(len(body) + 12)
		h := make([]byte, 8)
		binary.LittleEndian.PutUint32(h[0:4], t)
		binary.LittleEndian.PutUint32(h[4:8], l)
		out.Write(h)
		out.Write(body)
		tail := make([]byte, 4)
		binary.LittleEndian.PutUint32(tail, l)
		out.Write(tail)
	}
	shb := make([]byte, 16)
	binary.LittleEndian.PutUint32(shb[0:4], pcapngByteOrderMagic)
	binary.LittleEndian.PutUint16(shb[4:6], 1)
	binary.LittleEndian.PutUint16(shb[6:8], 0)
	for i := 8; i < 16; i++ {
		shb[i] = 0xff
	}
	wblock(pcapngBlockSectionHeader, shb)
	idb := make([]byte, 8)
	binary.LittleEndian.PutUint16(idb[0:2], uint16(linkType))
	binary.LittleEndian.PutUint32(idb[4:8], 65535)
	wblock(pcapngBlockInterfaceDesc, idb)
	pad := (4 - (len(payload) % 4)) % 4
	epb := make([]byte, 20+len(payload)+pad)
	binary.LittleEndian.PutUint32(epb[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint32(epb[16:20], uint32(len(payload)))
	copy(epb[20:], payload)
	sec := time.Unix(10, 0)
	binary.LittleEndian.PutUint32(epb[8:12], uint32(sec.Unix()*1_000_000))
	wblock(pcapngBlockEnhancedPacket, epb)
	return out.Bytes()
}
