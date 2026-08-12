package replay

import (
	"context"
	"fmt"
	"net"
	"time"

	"sip-tester/internal/pcapread"
)

type RTPReception struct {
	PacketCount   int
	FirstPacketAt time.Time
	LastPacketAt  time.Time
}

func DiscardPendingPackets(connection net.PacketConn) (int, error) {
	defer connection.SetReadDeadline(time.Time{})
	buffer := make([]byte, 64*1024)
	discarded := 0
	for {
		if err := connection.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			return discarded, fmt.Errorf("set packet drain deadline: %w", err)
		}
		if _, _, err := connection.ReadFrom(buffer); err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				return discarded, nil
			}
			return discarded, fmt.Errorf("drain packet: %w", err)
		}
		discarded++
	}
}

func WaitForRTPPackets(ctx context.Context, connection net.PacketConn, minimumPacketCount int) (RTPReception, error) {
	var reception RTPReception
	if minimumPacketCount <= 0 {
		return reception, nil
	}
	defer connection.SetReadDeadline(time.Time{})

	buffer := make([]byte, 64*1024)
	for reception.PacketCount < minimumPacketCount {
		readDeadline := time.Now().Add(250 * time.Millisecond)
		if contextDeadline, hasDeadline := ctx.Deadline(); hasDeadline && contextDeadline.Before(readDeadline) {
			readDeadline = contextDeadline
		}
		if err := connection.SetReadDeadline(readDeadline); err != nil {
			return reception, fmt.Errorf("set RTP read deadline: %w", err)
		}

		readCount, _, err := connection.ReadFrom(buffer)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				if contextError := ctx.Err(); contextError != nil {
					return reception, fmt.Errorf("received %d of %d required RTP packets: %w", reception.PacketCount, minimumPacketCount, contextError)
				}
				continue
			}
			return reception, fmt.Errorf("read RTP packet: %w", err)
		}

		receivedAt := time.Now()
		if _, isRTP := pcapread.ParseRTPPacket(buffer[:readCount], receivedAt); !isRTP {
			continue
		}
		if reception.PacketCount == 0 {
			reception.FirstPacketAt = receivedAt
		}
		reception.PacketCount++
		reception.LastPacketAt = receivedAt
	}
	return reception, nil
}
