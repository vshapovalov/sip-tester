package replay

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"sip-tester/internal/pcapread"
)

type MediaState string

const (
	MediaStateEarly MediaState = "early"
	MediaStateFinal MediaState = "final"
)

type MediaDestination struct {
	AudioAddr *net.UDPAddr
	VideoAddr *net.UDPAddr
	State     MediaState
}

type MediaDestinationStore struct {
	mu   sync.RWMutex
	dest MediaDestination
}

func (s *MediaDestinationStore) Set(dest MediaDestination) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dest = copyMediaDestination(dest)
}

func (s *MediaDestinationStore) Get() MediaDestination {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyMediaDestination(s.dest)
}

func copyMediaDestination(dest MediaDestination) MediaDestination {
	out := MediaDestination{State: dest.State}
	if dest.AudioAddr != nil {
		a := *dest.AudioAddr
		out.AudioAddr = &a
	}
	if dest.VideoAddr != nil {
		v := *dest.VideoAddr
		out.VideoAddr = &v
	}
	return out
}

type UDPSender struct {
	audioConn    net.PacketConn
	videoConn    net.PacketConn
	destinations *MediaDestinationStore
	ptMap        PayloadTypeMap
	now          func() time.Time
	sleep        func(time.Duration)
}

type PayloadTypeMap struct {
	Audio map[uint8]uint8
	Video map[uint8]uint8
}

func NewUDPSender(audioConn, videoConn net.PacketConn, destinations *MediaDestinationStore) *UDPSender {
	return NewUDPSenderWithPTMap(audioConn, videoConn, destinations, PayloadTypeMap{})
}

func NewUDPSenderWithPTMap(audioConn, videoConn net.PacketConn, destinations *MediaDestinationStore, ptMap PayloadTypeMap) *UDPSender {
	return &UDPSender{
		audioConn:    audioConn,
		videoConn:    videoConn,
		destinations: destinations,
		ptMap:        copyPayloadTypeMap(ptMap),
		now:          time.Now,
		sleep: func(d time.Duration) {
			time.Sleep(d)
		},
	}
}

// Replay sends RTP packets over UDP at their scheduled times and returns when done.
func (s *UDPSender) Replay(ctx context.Context, schedule []ScheduledPacket) error {
	start := s.now()
	for _, item := range schedule {
		target := start.Add(item.At)
		wait := target.Sub(s.now())
		if wait > 0 {
			if err := sleepWithContext(ctx, wait, s.sleep); err != nil {
				return err
			}
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		dest := s.destinations.Get()
		addr := destinationForPacket(dest, item)
		if addr == nil {
			continue
		}

		conn := s.connForMedia(item.MediaType)
		if conn == nil {
			continue
		}
		pkt := item.Packet
		if mappedPT, ok := s.ptMap.mapPayloadType(item.MediaType, pkt.PayloadType); ok {
			pkt.PayloadType = mappedPT
		}
		if _, err := conn.WriteTo(marshalRTP(pkt), addr); err != nil {
			return err
		}
	}

	return nil
}

func copyPayloadTypeMap(src PayloadTypeMap) PayloadTypeMap {
	out := PayloadTypeMap{}
	if len(src.Audio) > 0 {
		out.Audio = make(map[uint8]uint8, len(src.Audio))
		for from, to := range src.Audio {
			out.Audio[from] = to
		}
	}
	if len(src.Video) > 0 {
		out.Video = make(map[uint8]uint8, len(src.Video))
		for from, to := range src.Video {
			out.Video[from] = to
		}
	}
	return out
}

func (m PayloadTypeMap) mapPayloadType(mediaType MediaType, original uint8) (uint8, bool) {
	if original > 127 {
		return 0, false
	}
	switch mediaType {
	case MediaTypeAudio:
		if m.Audio == nil {
			return 0, false
		}
		mapped, ok := m.Audio[original]
		return mapped, ok
	case MediaTypeVideo:
		if m.Video == nil {
			return 0, false
		}
		mapped, ok := m.Video[original]
		return mapped, ok
	default:
		return 0, false
	}
}

func (s *UDPSender) connForMedia(mediaType MediaType) net.PacketConn {
	switch mediaType {
	case MediaTypeAudio:
		return s.audioConn
	case MediaTypeVideo:
		return s.videoConn
	default:
		return nil
	}
}

func destinationForPacket(dest MediaDestination, item ScheduledPacket) *net.UDPAddr {
	switch item.MediaType {
	case MediaTypeAudio:
		return dest.AudioAddr
	case MediaTypeVideo:
		return dest.VideoAddr
	default:
		return nil
	}
}

func sleepWithContext(ctx context.Context, d time.Duration, sleep func(time.Duration)) error {
	done := make(chan struct{})
	go func() {
		sleep(d)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func marshalRTP(pkt pcapread.RTPPacket) []byte {
	out := make([]byte, 12+len(pkt.Payload))
	out[0] = 2 << 6
	out[1] = pkt.PayloadType & 0x7f
	if pkt.Marker {
		out[1] |= 0x80
	}
	binary.BigEndian.PutUint16(out[2:4], pkt.Sequence)
	binary.BigEndian.PutUint32(out[4:8], pkt.Timestamp)
	binary.BigEndian.PutUint32(out[8:12], pkt.SSRC)
	copy(out[12:], pkt.Payload)
	return out
}
