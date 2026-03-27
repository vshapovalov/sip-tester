package pcapread

import (
	"errors"
	"testing"
	"time"
)

func TestFilterSSRC(t *testing.T) {
	streams := map[uint32][]RTPPacket{
		0x11223344: {
			{Sequence: 1, CaptureTime: time.Unix(10, 0)},
			{Sequence: 2, CaptureTime: time.Unix(11, 0)},
		},
		0xaabbccdd: {
			{Sequence: 100, CaptureTime: time.Unix(10, 0)},
		},
	}

	filtered, err := FilterSSRC(streams, 0x11223344)
	if err != nil {
		t.Fatalf("FilterSSRC returned error: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("len(filtered) = %d, want 1", len(filtered))
	}
	if len(filtered[0x11223344]) != 2 {
		t.Fatalf("len(filtered[0x11223344]) = %d, want 2", len(filtered[0x11223344]))
	}

	_, err = FilterSSRC(streams, 0xdeadbeef)
	if !errors.Is(err, ErrSSRCNotFound) {
		t.Fatalf("FilterSSRC missing SSRC error = %v, want ErrSSRCNotFound", err)
	}
}
