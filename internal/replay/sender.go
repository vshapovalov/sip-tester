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

type MediaSockets struct {
	AudioConn net.PacketConn
	VideoConn net.PacketConn
}

type MediaTransport struct {
	Sockets     MediaSockets
	Destination MediaDestination
}

type MediaTransportStore struct {
	mu        sync.RWMutex
	transport MediaTransport
}

func (store *MediaTransportStore) Set(transport MediaTransport) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.transport = copyMediaTransport(transport)
}

func (store *MediaTransportStore) SetDestination(destination MediaDestination) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.transport.Destination = copyMediaDestination(destination)
}

func (store *MediaTransportStore) Get() MediaTransport {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return copyMediaTransport(store.transport)
}

func copyMediaTransport(transport MediaTransport) MediaTransport {
	return MediaTransport{
		Sockets:     transport.Sockets,
		Destination: copyMediaDestination(transport.Destination),
	}
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
	transport *MediaTransportStore
	ptMap     PayloadTypeMap
	now       func() time.Time
	sleep     func(time.Duration)
}

type PayloadTypeMap struct {
	Audio map[uint8]uint8
	Video map[uint8]uint8
}

func NewUDPSender(audioConn, videoConn net.PacketConn, transport *MediaTransportStore) *UDPSender {
	return NewUDPSenderWithPTMap(audioConn, videoConn, transport, PayloadTypeMap{})
}

func NewUDPSenderWithPTMap(audioConn, videoConn net.PacketConn, transport *MediaTransportStore, ptMap PayloadTypeMap) *UDPSender {
	current := transport.Get()
	current.Sockets = MediaSockets{AudioConn: audioConn, VideoConn: videoConn}
	transport.Set(current)
	return NewUDPSenderWithTransport(transport, ptMap)
}

func NewUDPSenderWithTransport(transport *MediaTransportStore, ptMap PayloadTypeMap) *UDPSender {
	return &UDPSender{
		transport: transport,
		ptMap:     copyPayloadTypeMap(ptMap),
		now:       time.Now,
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

		transport := s.transport.Get()
		addr := destinationForPacket(transport.Destination, item)
		if addr == nil {
			continue
		}

		conn := connForMedia(transport.Sockets, item.MediaType)
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

func connForMedia(sockets MediaSockets, mediaType MediaType) net.PacketConn {
	switch mediaType {
	case MediaTypeAudio:
		return sockets.AudioConn
	case MediaTypeVideo:
		return sockets.VideoConn
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
