package pcapio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

func readPCAP(r io.Reader) ([]Packet, CaptureInfo, error) {
	hdr, err := readFull(r, 24)
	if err != nil {
		return nil, CaptureInfo{}, fmt.Errorf("cannot read pcap global header: %w", err)
	}

	magic := binary.BigEndian.Uint32(hdr[0:4])
	var order binary.ByteOrder
	nano := false
	switch magic {
	case 0xa1b2c3d4:
		order = binary.BigEndian
	case 0xd4c3b2a1:
		order = binary.LittleEndian
	case 0xa1b23c4d:
		order = binary.BigEndian
		nano = true
	case 0x4d3cb2a1:
		order = binary.LittleEndian
		nano = true
	default:
		return nil, CaptureInfo{}, fmt.Errorf("unsupported pcap magic 0x%08x", magic)
	}

	linkType := u32(hdr[20:24], order)
	out := make([]Packet, 0, 1024)
	for {
		recHdr, err := readFull(r, 16)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcap record header: %w", err)
		}
		sec := int64(u32(recHdr[0:4], order))
		frac := int64(u32(recHdr[4:8], order))
		incl := int(u32(recHdr[8:12], order))
		orig := int(u32(recHdr[12:16], order))
		if incl < 0 || incl > 64*1024*1024 || orig < incl {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcap record lengths incl=%d orig=%d", incl, orig)
		}
		payload, err := readFull(r, incl)
		if err != nil {
			return nil, CaptureInfo{}, fmt.Errorf("invalid pcap record payload: %w", err)
		}
		nsec := frac * 1000
		if nano {
			nsec = frac
		}
		if nsec < 0 || nsec > int64(math.MaxInt32) {
			nsec = 0
		}
		out = append(out, Packet{Timestamp: time.Unix(sec, nsec).UTC(), Data: bytes.Clone(payload), LinkType: linkType})
	}
	return out, CaptureInfo{Format: FormatPCAP, LinkTypes: []uint32{linkType}, Count: len(out)}, nil
}
