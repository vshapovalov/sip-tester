package pcapread

import (
	"fmt"
	"time"

	"sip-tester/internal/pcapio"
)

type Packet struct {
	Raw       pcapio.Packet
	Decoded   pcapio.DecodedPacket
	DecodeErr error
}

func LoadPCAP(path string) ([]Packet, error) {
	packets, _, err := LoadPCAPWithLinkType(path)
	return packets, err
}

func LoadPCAPWithLinkType(path string) ([]Packet, uint32, error) {
	raw, info, err := pcapio.ReadAll(path)
	if err != nil {
		return nil, 0, err
	}
	out := make([]Packet, 0, len(raw))
	var firstLinkType uint32
	if len(raw) > 0 {
		firstLinkType = raw[0].LinkType
	}
	for _, rp := range raw {
		dp, derr := pcapio.DecodePacket(rp)
		out = append(out, Packet{Raw: rp, Decoded: dp, DecodeErr: derr})
	}
	if len(out) == 0 {
		return nil, firstLinkType, fmt.Errorf("no packets in %s capture", info.Format)
	}
	return out, firstLinkType, nil
}

func CaptureDuration(packets []Packet) time.Duration {
	if len(packets) < 2 {
		return 0
	}
	start := packets[0].Raw.Timestamp
	end := packets[len(packets)-1].Raw.Timestamp
	if end.Before(start) {
		return 0
	}
	return end.Sub(start)
}
