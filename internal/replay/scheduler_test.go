package replay

import (
	"testing"
	"time"

	"sip-tester/internal/pcapread"
)

func TestBuildSchedule_MergesAndSortsByCaptureTime(t *testing.T) {
	base := time.Unix(100, 0)
	audio := []pcapread.RTPPacket{
		{SSRC: 1, Sequence: 10, CaptureTime: base.Add(20 * time.Millisecond)},
		{SSRC: 1, Sequence: 9, CaptureTime: base},
	}
	video := []pcapread.RTPPacket{
		{SSRC: 2, Sequence: 99, CaptureTime: base.Add(10 * time.Millisecond)},
	}

	schedule := BuildSchedule(audio, video)
	if len(schedule) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(schedule))
	}

	if got := schedule[0].Packet.Sequence; got != 9 {
		t.Fatalf("packet 0 sequence = %d, want 9", got)
	}
	if got := schedule[1].Packet.Sequence; got != 99 {
		t.Fatalf("packet 1 sequence = %d, want 99", got)
	}
	if got := schedule[2].Packet.Sequence; got != 10 {
		t.Fatalf("packet 2 sequence = %d, want 10", got)
	}

	if got := schedule[0].At; got != 0 {
		t.Fatalf("packet 0 At = %s, want 0", got)
	}
	if got := schedule[1].At; got != 10*time.Millisecond {
		t.Fatalf("packet 1 At = %s, want 10ms", got)
	}
	if got := schedule[2].At; got != 20*time.Millisecond {
		t.Fatalf("packet 2 At = %s, want 20ms", got)
	}
}

func TestBuildSchedule_EmptyInput(t *testing.T) {
	schedule := BuildSchedule(nil, nil)
	if schedule != nil {
		t.Fatalf("expected nil schedule, got %#v", schedule)
	}
}
