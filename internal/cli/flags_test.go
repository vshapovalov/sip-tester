package cli

import (
	"strings"
	"testing"
	"time"
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

func TestParseArgs_DetectsFamilyFromLocalIP(t *testing.T) {
	base := []string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	}

	cfg4, err := ParseArgs(append(base, "--local-ip", "192.0.2.10"))
	if err != nil {
		t.Fatalf("ParseArgs ipv4 error: %v", err)
	}
	if got := string(cfg4.IPFamily); got != "ipv4" {
		t.Fatalf("ipv4 family=%s", got)
	}

	cfg6, err := ParseArgs(append(base, "--local-ip", "2001:db8::10"))
	if err != nil {
		t.Fatalf("ParseArgs ipv6 error: %v", err)
	}
	if got := string(cfg6.IPFamily); got != "ipv6" {
		t.Fatalf("ipv6 family=%s", got)
	}
}

func TestParseArgs_ModeDefaultsToOutbound(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if cfg.Mode != "outbound" {
		t.Fatalf("mode=%s", cfg.Mode)
	}
}

func TestParseArgs_InvalidModeFails(t *testing.T) {
	_, err := ParseArgs([]string{
		"--mode", "foo",
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err == nil || !strings.Contains(err.Error(), "--mode must be one of") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_InboundDoesNotRequireCallee(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--mode", "inbound",
		"--caller", "1001",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if cfg.Callee != "" {
		t.Fatalf("callee should be empty, got %q", cfg.Callee)
	}
}

func TestParseArgs_OutboundStillRequiresCallee(t *testing.T) {
	_, err := ParseArgs([]string{
		"--mode", "outbound",
		"--caller", "1001",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err == nil || !strings.Contains(err.Error(), "--callee is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs_UserAgentDefault(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if got, want := cfg.UA, "sip-tester"; got != want {
		t.Fatalf("ua=%q, want %q", got, want)
	}
}

func TestParseArgs_UserAgentOverride(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
		"--ua", "My-UA/2.0",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if got, want := cfg.UA, "My-UA/2.0"; got != want {
		t.Fatalf("ua=%q, want %q", got, want)
	}
}

func TestParseArgs_AcceptsLifecycleControls(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--caller", "1001",
		"--callee", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
		"--header", "X-Speech-ID:repro-create-after-destroy",
		"--header", "X-Test-Run:run-1",
		"--cancel-after", "3s",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if got := cfg.Headers["X-Speech-ID"]; got != "repro-create-after-destroy" {
		t.Fatalf("X-Speech-ID=%q", got)
	}
	if got := cfg.Headers["X-Test-Run"]; got != "run-1" {
		t.Fatalf("X-Test-Run=%q", got)
	}
	if cfg.CancelAfter != 3*time.Second {
		t.Fatalf("cancel-after=%s", cfg.CancelAfter)
	}
}

func TestParseArgs_InboundReinviteAndBundle(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--mode", "inbound", "--caller", "1001", "--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10", "--pcap", "sample.pcap", "--ssrc-audio", "287454020",
		"--bundle", "--reinvite-after", "15s",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if !cfg.Bundle || cfg.ReinviteAfter != 15*time.Second {
		t.Fatalf("bundle=%t reinvite-after=%s", cfg.Bundle, cfg.ReinviteAfter)
	}
}

func TestParseArgs_ReinviteRequiresInboundMode(t *testing.T) {
	_, err := ParseArgs([]string{
		"--caller", "1001", "--callee", "1002", "--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.10", "--pcap", "sample.pcap", "--ssrc-audio", "287454020",
		"--reinvite-after", "15s",
	})
	if err == nil || !strings.Contains(err.Error(), "--reinvite-after requires --mode inbound") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgsHangupMode(t *testing.T) {
	for _, callMode := range []string{"outbound", "inbound"} {
		for _, hangupMode := range []string{"local", "remote", "invalid"} {
			t.Run(callMode+"/"+hangupMode, func(t *testing.T) {
				cfg, err := ParseArgs([]string{
					"--mode", callMode, "--hangup-mode", hangupMode,
					"--caller", "1001", "--callee", "1002",
					"--host", "127.0.0.1:5060", "--local-ip", "127.0.0.1",
					"--pcap", "call.pcap", "--ssrc-audio", "1234",
				})
				if hangupMode == "invalid" {
					if err == nil || !strings.Contains(err.Error(), "--hangup-mode must be one of") {
						t.Fatalf("expected hangup mode validation error, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("parse hangup mode: %v", err)
				}
				if cfg.HangupMode != hangupMode {
					t.Fatalf("hangup mode %q was not retained in config: %+v", hangupMode, cfg)
				}
			})
		}
	}
}

func TestParseArgs_AcceptsInboundTimingControls(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--mode", "inbound",
		"--caller", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.11",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
		"--answer-after", "750ms",
		"--registered-wait", "20s",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if cfg.AnswerAfter != 750*time.Millisecond {
		t.Fatalf("answer-after=%s", cfg.AnswerAfter)
	}
	if cfg.RegisteredWait != 20*time.Second {
		t.Fatalf("registered-wait=%s", cfg.RegisteredWait)
	}
}

func TestParseArgs_AcceptsInboundEarlyMediaVideoVerification(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--mode", "inbound",
		"--caller", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.11",
		"--pcap", "sample.pcap",
		"--ssrc-video", "0x259989ef",
		"--early-media",
		"--require-early-video-packets", "10",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if !cfg.EarlyMedia {
		t.Fatal("early media was not enabled")
	}
	if cfg.RequireEarlyVideoPackets != 10 {
		t.Fatalf("required early video packets=%d", cfg.RequireEarlyVideoPackets)
	}
}

func TestParseArgs_AcceptsInboundRejectAndFinalVideoVerification(t *testing.T) {
	commonArguments := []string{
		"--mode", "inbound",
		"--caller", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.11",
		"--pcap", "sample.pcap",
		"--ssrc-video", "0x259989ef",
		"--early-media",
		"--require-early-video-packets", "10",
	}
	for _, lifecycleArguments := range [][]string{
		{"--reject-after", "2s"},
		{"--answer-after", "2s", "--require-final-video-packets", "20"},
	} {
		_, err := ParseArgs(append(append([]string(nil), commonArguments...), lifecycleArguments...))
		if err != nil {
			t.Fatalf("ParseArgs(%v) error: %v", lifecycleArguments, err)
		}
	}
}

func TestParseArgs_EarlyMediaDefaultsRemainDisabled(t *testing.T) {
	cfg, err := ParseArgs([]string{
		"--mode", "inbound",
		"--caller", "1002",
		"--host", "pbx.example.com:5060",
		"--local-ip", "192.0.2.11",
		"--pcap", "sample.pcap",
		"--ssrc-audio", "287454020",
	})
	if err != nil {
		t.Fatalf("ParseArgs error: %v", err)
	}
	if cfg.EarlyMedia || cfg.RequireEarlyVideoPackets != 0 {
		t.Fatalf("unexpected early-media defaults: enabled=%t packets=%d", cfg.EarlyMedia, cfg.RequireEarlyVideoPackets)
	}
}

func TestParseArgs_RejectsInvalidLifecycleControls(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantError string
	}{
		{name: "malformed header", arguments: []string{"--header", "missing-separator"}, wantError: "--header"},
		{name: "duplicate header", arguments: []string{"--header", "X-Test:first", "--header", "X-Test:second"}, wantError: "duplicate header"},
		{name: "header injection", arguments: []string{"--header", "X-Test:ok\r\nRoute: attacker"}, wantError: "invalid header value"},
		{name: "transaction header", arguments: []string{"--header", "Via:attacker"}, wantError: "managed by sip-tester"},
		{name: "zero cancel delay", arguments: []string{"--cancel-after", "0s"}, wantError: "--cancel-after must be positive"},
		{name: "cancel in inbound mode", arguments: []string{"--mode", "inbound", "--cancel-after", "1s"}, wantError: "--cancel-after is only valid in outbound mode"},
		{name: "answer delay in outbound mode", arguments: []string{"--answer-after", "1s"}, wantError: "--answer-after is only valid in inbound mode"},
		{name: "reject delay in outbound mode", arguments: []string{"--reject-after", "1s"}, wantError: "--reject-after is only valid in inbound mode"},
		{name: "answer and reject together", arguments: []string{"--mode", "inbound", "--answer-after", "1s", "--reject-after", "1s"}, wantError: "--answer-after and --reject-after cannot be used together"},
		{name: "early media in outbound mode", arguments: []string{"--early-media"}, wantError: "--early-media is only valid in inbound mode"},
		{name: "negative early video packet count", arguments: []string{"--mode", "inbound", "--early-media", "--ssrc-video", "0x259989ef", "--require-early-video-packets", "-1"}, wantError: "--require-early-video-packets cannot be negative"},
		{name: "packet requirement without early media", arguments: []string{"--mode", "inbound", "--ssrc-video", "0x259989ef", "--require-early-video-packets", "10"}, wantError: "--require-early-video-packets requires --early-media"},
		{name: "packet requirement without video stream", arguments: []string{"--mode", "inbound", "--early-media", "--require-early-video-packets", "10"}, wantError: "--require-early-video-packets requires --ssrc-video"},
		{name: "negative final video packet count", arguments: []string{"--mode", "inbound", "--ssrc-video", "0x259989ef", "--require-final-video-packets", "-1"}, wantError: "--require-final-video-packets cannot be negative"},
		{name: "final video requirement in outbound mode", arguments: []string{"--ssrc-video", "0x259989ef", "--require-final-video-packets", "10"}, wantError: "--require-final-video-packets is only valid in inbound mode"},
		{name: "final packet requirement without video stream", arguments: []string{"--mode", "inbound", "--require-final-video-packets", "10"}, wantError: "--require-final-video-packets requires --ssrc-video"},
		{name: "final packet requirement on rejected call", arguments: []string{"--mode", "inbound", "--ssrc-video", "0x259989ef", "--reject-after", "1s", "--require-final-video-packets", "10"}, wantError: "--require-final-video-packets cannot be used with --reject-after"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := []string{
				"--caller", "1001",
				"--callee", "1002",
				"--host", "pbx.example.com:5060",
				"--local-ip", "192.0.2.10",
				"--pcap", "sample.pcap",
				"--ssrc-audio", "287454020",
			}
			arguments = append(arguments, test.arguments...)
			_, err := ParseArgs(arguments)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want containing %q", err, test.wantError)
			}
		})
	}
}
