package replay

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"sip-tester/internal/pcapread"
)

type UDPSender struct {
	conn  net.PacketConn
	addr  net.Addr
	now   func() time.Time
	sleep func(time.Duration)
}

func NewUDPSender(conn net.PacketConn, addr net.Addr) *UDPSender {
	return &UDPSender{
		conn: conn,
		addr: addr,
		now:  time.Now,
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

		if _, err := s.conn.WriteTo(marshalRTP(item.Packet), s.addr); err != nil {
			return err
		}
	}

	return nil
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
