package pcapread

import (
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// LoadPCAP reads an entire pcap file and decodes all packets.
func LoadPCAP(path string) ([]gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make([]gopacket.Packet, 0, 1024)

	for {
		packet, err := source.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode pcap packet: %w", err)
		}
		packets = append(packets, packet)
	}

	return packets, nil
}

// CaptureDuration returns the wall-clock capture duration between first and last packet.
func CaptureDuration(packets []gopacket.Packet) time.Duration {
	if len(packets) < 2 {
		return 0
	}
	start := packets[0].Metadata().CaptureInfo.Timestamp
	end := packets[len(packets)-1].Metadata().CaptureInfo.Timestamp
	if end.Before(start) {
		return 0
	}
	return end.Sub(start)
}
