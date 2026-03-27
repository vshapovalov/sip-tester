package replay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"sip-tester/internal/pcapread"
)

func TestUDPSenderReplay_PreservesRTPFields(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen receiver: %v", err)
	}
	defer receiver.Close()

	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	defer senderConn.Close()

	s := NewUDPSender(senderConn, receiver.LocalAddr())
	pkt := pcapread.RTPPacket{
		Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
		Sequence:    4321,
		Timestamp:   0x10203040,
		SSRC:        0xaabbccdd,
		PayloadType: 96,
		Marker:      true,
	}

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := receiver.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		raw := buf[:n]
		if len(raw) != 12+len(pkt.Payload) {
			errCh <- errors.New("unexpected RTP size")
			return
		}
		if raw[0]>>6 != 2 {
			errCh <- errors.New("invalid RTP version")
			return
		}
		if got := binary.BigEndian.Uint16(raw[2:4]); got != pkt.Sequence {
			errCh <- errors.New("sequence mismatch")
			return
		}
		if got := binary.BigEndian.Uint32(raw[4:8]); got != pkt.Timestamp {
			errCh <- errors.New("timestamp mismatch")
			return
		}
		if got := binary.BigEndian.Uint32(raw[8:12]); got != pkt.SSRC {
			errCh <- errors.New("ssrc mismatch")
			return
		}
		if got := raw[1] & 0x7f; got != pkt.PayloadType {
			errCh <- errors.New("payload type mismatch")
			return
		}
		if got := raw[1]&0x80 != 0; got != pkt.Marker {
			errCh <- errors.New("marker mismatch")
			return
		}
		if string(raw[12:]) != string(pkt.Payload) {
			errCh <- errors.New("payload mismatch")
			return
		}
		errCh <- nil
	}()

	err = s.Replay(context.Background(), []ScheduledPacket{{At: 0, Packet: pkt}})
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("received packet validation failed: %v", err)
	}
}

func TestUDPSenderReplay_StopsOnContextCancel(t *testing.T) {
	s := &UDPSender{
		now: func() time.Time { return time.Unix(0, 0) },
		sleep: func(d time.Duration) {
			time.Sleep(100 * time.Millisecond)
		},
		conn: &recordingConn{},
		addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Replay(ctx, []ScheduledPacket{{At: time.Second, Packet: pcapread.RTPPacket{}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

type recordingConn struct{}

func (r *recordingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, nil }
func (r *recordingConn) WriteTo(p []byte, addr net.Addr) (n int, err error)  { return len(p), nil }
func (r *recordingConn) Close() error                                        { return nil }
func (r *recordingConn) LocalAddr() net.Addr                                 { return &net.UDPAddr{} }
func (r *recordingConn) SetDeadline(t time.Time) error                       { return nil }
func (r *recordingConn) SetReadDeadline(t time.Time) error                   { return nil }
func (r *recordingConn) SetWriteDeadline(t time.Time) error                  { return nil }
