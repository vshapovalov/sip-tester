package replay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWaitForRTPPacketsIgnoresMalformedDatagrams(t *testing.T) {
	receiver := listenTestUDP(t)
	sender := listenTestUDP(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resultChannel := make(chan struct {
		reception RTPReception
		err       error
	}, 1)
	go func() {
		reception, err := WaitForRTPPackets(ctx, receiver, 2)
		resultChannel <- struct {
			reception RTPReception
			err       error
		}{reception: reception, err: err}
	}()

	for _, datagram := range [][]byte{
		[]byte("not rtp"),
		buildReceivedRTPPacket(10, 0x11223344),
		buildReceivedRTPPacket(11, 0x11223344),
	} {
		if _, err := sender.WriteToUDP(datagram, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("send datagram: %v", err)
		}
	}

	result := <-resultChannel
	if result.err != nil {
		t.Fatalf("WaitForRTPPackets error: %v", result.err)
	}
	if result.reception.PacketCount != 2 {
		t.Fatalf("packet count=%d", result.reception.PacketCount)
	}
	if result.reception.FirstPacketAt.IsZero() || result.reception.LastPacketAt.Before(result.reception.FirstPacketAt) {
		t.Fatalf("invalid reception timestamps: %+v", result.reception)
	}
}

func TestWaitForRTPPacketsReportsCountOnTimeout(t *testing.T) {
	receiver := listenTestUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	reception, err := WaitForRTPPackets(ctx, receiver, 1)
	if err == nil || !strings.Contains(err.Error(), "received 0 of 1") {
		t.Fatalf("error=%v", err)
	}
	if reception.PacketCount != 0 {
		t.Fatalf("packet count=%d", reception.PacketCount)
	}
}

func TestWaitForRTPPacketsDoesNotCountPacketsAfterCancellation(t *testing.T) {
	for _, cancellationPoint := range []string{"before_wait", "during_read"} {
		t.Run(cancellationPoint, func(t *testing.T) {
			receiver := listenTestUDP(t)
			sender := listenTestUDP(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelAndSendPacket := func() {
				cancel()
				if _, err := sender.WriteToUDP(buildReceivedRTPPacket(1, 0x11223344), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
					t.Fatal(err)
				}
			}
			var connection net.PacketConn = receiver
			if cancellationPoint == "before_wait" {
				cancelAndSendPacket()
			} else {
				connection = &cancelOnReadPacketConn{PacketConn: receiver, cancelAndSendPacket: cancelAndSendPacket}
			}
			reception, err := WaitForRTPPackets(ctx, connection, 1)
			if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "received 0 of 1 required RTP packets") {
				t.Fatalf("expected cancellation with missing packet count, got reception=%+v error=%v", reception, err)
			}
			if reception.PacketCount != 0 {
				t.Fatalf("counted packets after cancellation: %d", reception.PacketCount)
			}
		})
	}
}

type cancelOnReadPacketConn struct {
	net.PacketConn
	cancelAndSendPacket func()
}

func (connection *cancelOnReadPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	connection.cancelAndSendPacket()
	return connection.PacketConn.ReadFrom(packet)
}

func TestWaitForRTPPacketsReturnsImmediatelyWhenNoPacketsAreRequired(t *testing.T) {
	reception, err := WaitForRTPPackets(context.Background(), nil, 0)
	if err != nil {
		t.Fatalf("WaitForRTPPackets error: %v", err)
	}
	if reception.PacketCount != 0 || !reception.FirstPacketAt.IsZero() || !reception.LastPacketAt.IsZero() {
		t.Fatalf("unexpected reception: %+v", reception)
	}
}

func TestWaitForRTPPacketsReportsClosedConnection(t *testing.T) {
	receiver := listenTestUDP(t)
	if err := receiver.Close(); err != nil {
		t.Fatalf("close receiver: %v", err)
	}

	_, err := WaitForRTPPackets(context.Background(), receiver, 1)
	if err == nil || !strings.Contains(err.Error(), "set RTP read deadline") {
		t.Fatalf("error=%v", err)
	}
}

func TestDiscardPendingPacketsLeavesOnlyPacketsSentAfterDrain(t *testing.T) {
	receiver := listenTestUDP(t)
	sender := listenTestUDP(t)
	for sequence := uint16(1); sequence <= 3; sequence++ {
		if _, err := sender.WriteToUDP(buildReceivedRTPPacket(sequence, 0x11223344), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("send pending packet: %v", err)
		}
	}

	discarded, err := DiscardPendingPackets(receiver)
	if err != nil {
		t.Fatalf("DiscardPendingPackets error: %v", err)
	}
	if discarded != 3 {
		t.Fatalf("discarded packets=%d", discarded)
	}

	if _, err := sender.WriteToUDP(buildReceivedRTPPacket(4, 0x11223344), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send final packet: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reception, err := WaitForRTPPackets(ctx, receiver, 1)
	if err != nil {
		t.Fatalf("WaitForRTPPackets error: %v", err)
	}
	if reception.PacketCount != 1 {
		t.Fatalf("final packet count=%d", reception.PacketCount)
	}
}

func TestDiscardPendingPacketsReportsClosedConnection(t *testing.T) {
	receiver := listenTestUDP(t)
	if err := receiver.Close(); err != nil {
		t.Fatalf("close receiver: %v", err)
	}

	discarded, err := DiscardPendingPackets(receiver)
	if err == nil || !strings.Contains(err.Error(), "set packet drain deadline") {
		t.Fatalf("discarded=%d error=%v", discarded, err)
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func buildReceivedRTPPacket(sequence uint16, ssrc uint32) []byte {
	packet := make([]byte, 13)
	packet[0] = 2 << 6
	packet[1] = 96
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], uint32(sequence)*3000)
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	packet[12] = 0x65
	return packet
}
