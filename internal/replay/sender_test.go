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

	store := &MediaDestinationStore{}
	store.Set(MediaDestination{AudioAddr: receiver.LocalAddr().(*net.UDPAddr), State: MediaStateEarly})
	s := NewUDPSender(senderConn, senderConn, store)
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

	err = s.Replay(context.Background(), []ScheduledPacket{{At: 0, MediaType: MediaTypeAudio, Packet: pkt}})
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
		audioConn:    &recordingConn{},
		videoConn:    &recordingConn{},
		destinations: &MediaDestinationStore{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Replay(ctx, []ScheduledPacket{{At: time.Second, MediaType: MediaTypeAudio, Packet: pcapread.RTPPacket{}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestUDPSenderReplay_SkipsUntilDestinationAvailable(t *testing.T) {
	conn := &recordingConn{}
	store := &MediaDestinationStore{}
	s := NewUDPSender(conn, conn, store)
	s.now = sequencedNow([]time.Time{time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0)})
	s.sleep = func(time.Duration) {}

	err := s.Replay(context.Background(), []ScheduledPacket{{At: 0, MediaType: MediaTypeAudio, Packet: pcapread.RTPPacket{Payload: []byte{1}}}})
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}
	if len(conn.writes) != 0 {
		t.Fatalf("expected no writes, got %d", len(conn.writes))
	}
}

func TestUDPSenderReplay_SwitchesDestinationDuringReplay(t *testing.T) {
	conn := &recordingConn{}
	store := &MediaDestinationStore{}
	a1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}
	a2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
	store.Set(MediaDestination{AudioAddr: a1, State: MediaStateEarly})
	s := NewUDPSender(conn, conn, store)
	s.now = sequencedNow([]time.Time{
		time.Unix(0, 0),
		time.Unix(0, 0),
		time.Unix(0, 0),
		time.Unix(0, 0),
		time.Unix(0, 0).Add(2 * time.Millisecond),
	})
	s.sleep = func(time.Duration) {
		store.Set(MediaDestination{AudioAddr: a2, State: MediaStateFinal})
	}

	err := s.Replay(context.Background(), []ScheduledPacket{
		{At: 0, MediaType: MediaTypeAudio, Packet: pcapread.RTPPacket{Payload: []byte{1}}},
		{At: time.Millisecond, MediaType: MediaTypeAudio, Packet: pcapread.RTPPacket{Payload: []byte{2}}},
	})
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(conn.writes))
	}
	if conn.writes[0].addr.String() != a1.String() {
		t.Fatalf("first packet addr=%s want=%s", conn.writes[0].addr, a1)
	}
	if conn.writes[1].addr.String() != a2.String() {
		t.Fatalf("second packet addr=%s want=%s", conn.writes[1].addr, a2)
	}
}

func TestMediaDestinationStore_MultipleEarlyUpdates(t *testing.T) {
	store := &MediaDestinationStore{}
	first := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}
	second := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}

	store.Set(MediaDestination{AudioAddr: first, State: MediaStateEarly})
	store.Set(MediaDestination{AudioAddr: second, State: MediaStateEarly})
	got := store.Get()
	if got.AudioAddr == nil || got.AudioAddr.String() != second.String() {
		t.Fatalf("audio destination=%v want=%v", got.AudioAddr, second)
	}
}

type writeRecord struct {
	addr net.Addr
	data []byte
}

type recordingConn struct{ writes []writeRecord }

func (r *recordingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, nil }
func (r *recordingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, writeRecord{addr: addr, data: cp})
	return len(p), nil
}
func (r *recordingConn) Close() error                       { return nil }
func (r *recordingConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (r *recordingConn) SetDeadline(t time.Time) error      { return nil }
func (r *recordingConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *recordingConn) SetWriteDeadline(t time.Time) error { return nil }

func sequencedNow(values []time.Time) func() time.Time {
	idx := 0
	return func() time.Time {
		if idx >= len(values) {
			return values[len(values)-1]
		}
		v := values[idx]
		idx++
		return v
	}
}

func TestUDPSenderReplay_UsesSeparateAudioAndVideoSockets(t *testing.T) {
	audioConn := &recordingConn{}
	videoConn := &recordingConn{}
	store := &MediaDestinationStore{}
	store.Set(MediaDestination{
		AudioAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000},
		VideoAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
		State:     MediaStateFinal,
	})
	s := NewUDPSender(audioConn, videoConn, store)
	s.now = sequencedNow([]time.Time{time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0), time.Unix(0, 0)})
	s.sleep = func(time.Duration) {}

	err := s.Replay(context.Background(), []ScheduledPacket{
		{At: 0, MediaType: MediaTypeAudio, Packet: pcapread.RTPPacket{Payload: []byte{1}}},
		{At: 0, MediaType: MediaTypeVideo, Packet: pcapread.RTPPacket{Payload: []byte{2}}},
	})
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}
	if len(audioConn.writes) != 1 {
		t.Fatalf("expected 1 audio write, got %d", len(audioConn.writes))
	}
	if len(videoConn.writes) != 1 {
		t.Fatalf("expected 1 video write, got %d", len(videoConn.writes))
	}
}
