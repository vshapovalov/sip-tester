package pcapio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	pcapngBlockSectionHeader         = 0x0A0D0D0A
	pcapngBlockInterfaceDesc         = 0x00000001
	pcapngBlockEnhancedPacket        = 0x00000006
	pcapngByteOrderMagic             = 0x1A2B3C4D
	pcapngOptionIfTSResol     uint16 = 9
)

type pcapngInterface struct {
	linkType uint32
	tsScale  int64
}

func readPCAPNG(r io.Reader) ([]Packet, CaptureInfo, error) {
	interfaces := map[uint32]pcapngInterface{}
	var order binary.ByteOrder = binary.LittleEndian
	inSection := false
	out := make([]Packet, 0, 1024)
	linkTypesSeen := map[uint32]bool{}

	for {
		h, err := readFull(r, 8)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng block header: %w", err)
		}
		blockType := binary.LittleEndian.Uint32(h[0:4])
		blockLen := binary.LittleEndian.Uint32(h[4:8])
		if blockLen < 12 {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng block length %d", blockLen)
		}
		body, err := readFull(r, int(blockLen)-8)
		if err != nil {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng block payload: %w", err)
		}

		if int(blockLen) > len(body)+8 {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng block length")
		}
		trailer := body[len(body)-4:]
		if binary.LittleEndian.Uint32(trailer) != blockLen {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng trailing block length")
		}
		payload := body[:len(body)-4]

		switch blockType {
		case pcapngBlockSectionHeader:
			if len(payload) < 16 {
				return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng section header")
			}
			bom := binary.LittleEndian.Uint32(payload[0:4])
			switch bom {
			case pcapngByteOrderMagic:
				order = binary.LittleEndian
			case 0x4D3C2B1A:
				order = binary.BigEndian
			default:
				return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng byte-order magic 0x%08x", bom)
			}
			interfaces = map[uint32]pcapngInterface{}
			inSection = true
		case pcapngBlockInterfaceDesc:
			if !inSection || len(payload) < 8 {
				continue
			}
			linkType := uint32(u16(payload[0:2], order))
			opts := payload[8:]
			iface := pcapngInterface{linkType: linkType, tsScale: 1_000_000}
			for len(opts) >= 4 {
				code := u16(opts[0:2], order)
				ln := int(u16(opts[2:4], order))
				opts = opts[4:]
				if ln > len(opts) {
					break
				}
				value := opts[:ln]
				pad := (4 - (ln % 4)) % 4
				if ln+pad > len(opts) {
					break
				}
				opts = opts[ln+pad:]
				if code == 0 {
					break
				}
				if code == pcapngOptionIfTSResol && len(value) == 1 {
					iface.tsScale = tsScaleFromResol(value[0])
				}
			}
			interfaces[uint32(len(interfaces))] = iface
			linkTypesSeen[linkType] = true
		case pcapngBlockEnhancedPacket:
			if len(payload) < 20 {
				return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng enhanced packet block")
			}
			ifaceID := u32(payload[0:4], order)
			iface, ok := interfaces[ifaceID]
			if !ok {
				return nil, CaptureInfo{}, fmt.Errorf("pcapng packet references unknown interface %d", ifaceID)
			}
			tsh := u32(payload[4:8], order)
			tsl := u32(payload[8:12], order)
			capLen := int(u32(payload[12:16], order))
			if capLen < 0 || 20+capLen > len(payload) {
				return nil, CaptureInfo{}, fmt.Errorf("invalid pcapng captured length %d", capLen)
			}
			pkt := bytes.Clone(payload[20 : 20+capLen])
			ticks := (int64(tsh) << 32) | int64(tsl)
			sec, nsec := ticksToUnix(ticks, iface.tsScale)
			out = append(out, Packet{Timestamp: time.Unix(sec, nsec).UTC(), Data: pkt, LinkType: iface.linkType})
		}
	}

	links := make([]uint32, 0, len(linkTypesSeen))
	for lt := range linkTypesSeen {
		links = append(links, lt)
	}
	return out, CaptureInfo{Format: FormatPCAPNG, LinkTypes: links, Count: len(out)}, nil
}

func tsScaleFromResol(v byte) int64 {
	if v&0x80 == 0 {
		exp := int(v & 0x7f)
		s := int64(1)
		for i := 0; i < exp && s < math.MaxInt64/10; i++ {
			s *= 10
		}
		if s == 0 {
			return 1_000_000
		}
		return s
	}
	exp := int(v & 0x7f)
	s := int64(1)
	for i := 0; i < exp && s < math.MaxInt64/2; i++ {
		s *= 2
	}
	if s == 0 {
		return 1_000_000
	}
	return s
}

func ticksToUnix(ticks, scale int64) (sec int64, nsec int64) {
	if scale <= 0 {
		scale = 1_000_000
	}
	sec = ticks / scale
	rem := ticks % scale
	nsec = rem * int64(time.Second) / scale
	return sec, nsec
}
