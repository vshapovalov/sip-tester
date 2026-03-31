package pcapread

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// ExtractRTPBySSRC parses RTP packets from UDP payloads and groups them by SSRC.
func ExtractRTPBySSRC(packets []gopacket.Packet) map[uint32][]RTPPacket {
	streams := map[uint32][]RTPPacket{}
	for _, packet := range packets {
		udp, ok := packet.TransportLayer().(*layers.UDP)
		if !ok {
			continue
		}

		rtp, ok := parseRTPPacket(udp.Payload, packet.Metadata().CaptureInfo.Timestamp)
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

// DecodableUDPCount returns the number of packets that decoded a UDP transport layer.
func DecodableUDPCount(packets []gopacket.Packet) int {
	count := 0
	for _, packet := range packets {
		if _, ok := packet.TransportLayer().(*layers.UDP); ok {
			count++
		}
	}
	return count
}

// FilterSSRC keeps only requested SSRC streams and returns error when any requested SSRC is missing.
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

// StreamDuration returns the timespan between first and last RTP packet in one stream.
func StreamDuration(pkts []RTPPacket) time.Duration {
	if len(pkts) < 2 {
		return 0
	}
	start := pkts[0].CaptureTime
	end := pkts[len(pkts)-1].CaptureTime
	if end.Before(start) {
		return 0
	}
	return end.Sub(start)
}

func parseRTPPacket(payload []byte, captureTime time.Time) (RTPPacket, bool) {
	if len(payload) < 12 {
		return RTPPacket{}, false
	}
	if payload[0]>>6 != 2 {
		return RTPPacket{}, false
	}

	cc := int(payload[0] & 0x0f)
	headerLen := 12 + cc*4
	if len(payload) < headerLen {
		return RTPPacket{}, false
	}

	if payload[0]&0x10 != 0 {
		if len(payload) < headerLen+4 {
			return RTPPacket{}, false
		}
		extLenWords := int(binary.BigEndian.Uint16(payload[headerLen+2 : headerLen+4]))
		headerLen += 4 + extLenWords*4
		if len(payload) < headerLen {
			return RTPPacket{}, false
		}
	}

	padLen := 0
	if payload[0]&0x20 != 0 {
		padLen = int(payload[len(payload)-1])
		if padLen > len(payload)-headerLen {
			return RTPPacket{}, false
		}
	}

	out := RTPPacket{
		Sequence:    binary.BigEndian.Uint16(payload[2:4]),
		Timestamp:   binary.BigEndian.Uint32(payload[4:8]),
		Marker:      payload[1]&0x80 != 0,
		PayloadType: payload[1] & 0x7f,
		SSRC:        binary.BigEndian.Uint32(payload[8:12]),
		CaptureTime: captureTime,
	}
	out.Payload = append([]byte(nil), payload[headerLen:len(payload)-padLen]...)
	return out, true
}
