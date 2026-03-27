package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type record struct {
	ci   gopacket.CaptureInfo
	data []byte
}

type Handle struct {
	linkType layers.LinkType
	records  []record
	idx      int
}

func OpenOffline(path string) (*Handle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 24 {
		return nil, fmt.Errorf("invalid pcap: too short")
	}

	magic := binary.LittleEndian.Uint32(b[:4])
	little := true
	switch magic {
	case 0xa1b2c3d4:
		little = true
	case 0xd4c3b2a1:
		little = false
	default:
		return nil, fmt.Errorf("unsupported pcap magic: 0x%x", magic)
	}

	u32 := func(in []byte) uint32 {
		if little {
			return binary.LittleEndian.Uint32(in)
		}
		return binary.BigEndian.Uint32(in)
	}

	network := u32(b[20:24])
	h := &Handle{linkType: layers.LinkType(network)}
	off := 24
	for off+16 <= len(b) {
		tsSec := u32(b[off : off+4])
		tsUsec := u32(b[off+4 : off+8])
		inclLen := int(u32(b[off+8 : off+12]))
		off += 16
		if inclLen < 0 || off+inclLen > len(b) {
			return nil, fmt.Errorf("invalid pcap record length")
		}
		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)
		h.records = append(h.records, record{
			ci:   gopacket.CaptureInfo{Timestamp: ts},
			data: append([]byte(nil), b[off:off+inclLen]...),
		})
		off += inclLen
	}

	return h, nil
}

func (h *Handle) Close() error { return nil }

func (h *Handle) LinkType() layers.LinkType { return h.linkType }

func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if h.idx >= len(h.records) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	r := h.records[h.idx]
	h.idx++
	return append([]byte(nil), r.data...), r.ci, nil
}
