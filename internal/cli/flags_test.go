package cli

import (
	"strings"
	"testing"
)

func TestParseSSRC(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{in: "287454020", want: 0x11223344},
		{in: "0x11223344", want: 0x11223344},
	}

	for _, tt := range tests {
		got, err := ParseSSRC(tt.in)
		if err != nil {
			t.Fatalf("ParseSSRC(%q) returned error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseSSRC(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	_, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
	})
	if err == nil {
		t.Fatal("expected error for missing both ssrc flags")
	}
	if !strings.Contains(err.Error(), "at least one of --ssrc-audio or --ssrc-video") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "not-an-ip",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err == nil {
		t.Fatal("expected local-ip validation error")
	}
	if !strings.Contains(err.Error(), "--local-ip must be a literal IP address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidationErrorsCredentialsPair(t *testing.T) {
	_, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
		"--username", "1001",
	})
	if err == nil {
		t.Fatal("expected credential pairing validation error")
	}
	if !strings.Contains(err.Error(), "--username and --password must be provided together") {
		t.Fatalf("unexpected error: %v", err)
	}
}
