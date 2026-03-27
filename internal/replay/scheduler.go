package replay

import (
	"sort"
	"time"

	"sip-tester/internal/pcapread"
)

type MediaType string

const (
	MediaTypeAudio MediaType = "audio"
	MediaTypeVideo MediaType = "video"
)

// ScheduledPacket represents an RTP packet with its offset from the first packet in a replay run.
type ScheduledPacket struct {
	At        time.Duration
	MediaType MediaType
	Packet    pcapread.RTPPacket
}

// BuildSchedule merges audio and video RTP streams into one time-ordered replay schedule.
func BuildSchedule(audio, video []pcapread.RTPPacket) []ScheduledPacket {
	merged := make([]ScheduledPacket, 0, len(audio)+len(video))
	for _, pkt := range audio {
		merged = append(merged, ScheduledPacket{MediaType: MediaTypeAudio, Packet: pkt})
	}
	for _, pkt := range video {
		merged = append(merged, ScheduledPacket{MediaType: MediaTypeVideo, Packet: pkt})
	}
	if len(merged) == 0 {
		return nil
	}

	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Packet.CaptureTime.Before(merged[j].Packet.CaptureTime)
	})

	start := merged[0].Packet.CaptureTime
	schedule := make([]ScheduledPacket, 0, len(merged))
	for _, item := range merged {
		offset := item.Packet.CaptureTime.Sub(start)
		if offset < 0 {
			offset = 0
		}
		item.At = offset
		schedule = append(schedule, item)
	}

	return schedule
}
