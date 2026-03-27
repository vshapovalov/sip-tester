package replay

import (
	"sort"
	"time"

	"sip-tester/internal/pcapread"
)

// ScheduledPacket represents an RTP packet with its offset from the first packet in a replay run.
type ScheduledPacket struct {
	At     time.Duration
	Packet pcapread.RTPPacket
}

// BuildSchedule merges audio and video RTP streams into one time-ordered replay schedule.
func BuildSchedule(audio, video []pcapread.RTPPacket) []ScheduledPacket {
	merged := make([]pcapread.RTPPacket, 0, len(audio)+len(video))
	merged = append(merged, audio...)
	merged = append(merged, video...)
	if len(merged) == 0 {
		return nil
	}

	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].CaptureTime.Before(merged[j].CaptureTime)
	})

	start := merged[0].CaptureTime
	schedule := make([]ScheduledPacket, 0, len(merged))
	for _, pkt := range merged {
		offset := pkt.CaptureTime.Sub(start)
		if offset < 0 {
			offset = 0
		}
		schedule = append(schedule, ScheduledPacket{At: offset, Packet: pkt})
	}

	return schedule
}
