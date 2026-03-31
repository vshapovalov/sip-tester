package pcapread

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrSSRCNotFound = errors.New("ssrc not found")

type RTPPacket struct {
	Payload     []byte
	Sequence    uint16
	Timestamp   uint32
	Marker      bool
	PayloadType uint8
	SSRC        uint32
	CaptureTime time.Time
}

func ExtractRTPBySSRC(packets []Packet) map[uint32][]RTPPacket {
	streams := map[uint32][]RTPPacket{}
	for _, packet := range packets {
		if packet.DecodeErr != nil || !packet.Decoded.IsUDP {
			continue
		}
		rtp, ok := parseRTPPacket(packet.Decoded.Payload, packet.Decoded.Timestamp)
		if !ok {
			continue
		}
		streams[rtp.SSRC] = append(streams[rtp.SSRC], rtp)
	}
	for ssrc := range streams {
		sort.Slice(streams[ssrc], func(i, j int) bool {
			return streams[ssrc][i].CaptureTime.Before(streams[ssrc][j].CaptureTime)
		})
	}
	return streams
}

func DecodableUDPCount(packets []Packet) int {
	count := 0
	for _, packet := range packets {
		if packet.DecodeErr == nil && packet.Decoded.IsUDP {
			count++
		}
	}
	return count
}

func FilterSSRC(streams map[uint32][]RTPPacket, requested ...uint32) (map[uint32][]RTPPacket, error) {
	filtered := make(map[uint32][]RTPPacket, len(requested))
	for _, ssrc := range requested {
		pkts, ok := streams[ssrc]
		if !ok {
			return nil, fmt.Errorf("%w: 0x%08x", ErrSSRCNotFound, ssrc)
		}
		filtered[ssrc] = pkts
	}
	return filtered, nil
}

func StreamDuration(pkts []RTPPacket) time.Duration {
	if len(pkts) < 2 {
		return 0
	}
	if pkts[len(pkts)-1].CaptureTime.Before(pkts[0].CaptureTime) {
		return 0
	}
	return pkts[len(pkts)-1].CaptureTime.Sub(pkts[0].CaptureTime)
}

func parseRTPPacket(payload []byte, captureTime time.Time) (RTPPacket, bool) {
	if len(payload) < 12 || payload[0]>>6 != 2 {
		return RTPPacket{}, false
	}
	cc := int(payload[0] & 0x0f)
	hl := 12 + cc*4
	if len(payload) < hl {
		return RTPPacket{}, false
	}
	if payload[0]&0x10 != 0 {
		if len(payload) < hl+4 {
			return RTPPacket{}, false
		}
		extLen := int(binary.BigEndian.Uint16(payload[hl+2 : hl+4]))
		hl += 4 + extLen*4
		if len(payload) < hl {
			return RTPPacket{}, false
		}
	}
	pad := 0
	if payload[0]&0x20 != 0 {
		pad = int(payload[len(payload)-1])
		if pad > len(payload)-hl {
			return RTPPacket{}, false
		}
	}
	out := RTPPacket{Sequence: binary.BigEndian.Uint16(payload[2:4]), Timestamp: binary.BigEndian.Uint32(payload[4:8]), Marker: payload[1]&0x80 != 0, PayloadType: payload[1] & 0x7f, SSRC: binary.BigEndian.Uint32(payload[8:12]), CaptureTime: captureTime}
	out.Payload = append([]byte(nil), payload[hl:len(payload)-pad]...)
	return out, true
}
