package config

import (
	"strings"
	"testing"
)

func TestValidateRequiredDefaultsToLocalHangup(t *testing.T) {
	configuration := Config{
		CallerRaw: "1001", CalleeRaw: "1002", HostRaw: "127.0.0.1:5060",
		LocalIP: "127.0.0.1", PCAP: "call.pcap", SSRCAudioRaw: "1234",
	}
	if err := configuration.ValidateRequired(); err != nil {
		t.Fatal(err)
	}
	if configuration.HangupMode != "local" {
		t.Fatalf("default hangup mode=%q, want local", configuration.HangupMode)
	}
	if configuration.Transport != "udp" {
		t.Fatalf("default signaling transport=%q, want udp", configuration.Transport)
	}
}

func TestValidateRequiredSignalingTransportOptions(t *testing.T) {
	scenarios := []struct {
		name          string
		transport     string
		caFile        string
		isInsecure    bool
		errorContains string
	}{
		{name: "UDP", transport: "udp"},
		{name: "TCP", transport: "tcp"},
		{name: "TLS", transport: "tls"},
		{name: "TLS custom CA", transport: "tls", caFile: "test-ca.pem"},
		{name: "TLS insecure opt in", transport: "tls", isInsecure: true},
		{name: "unsupported transport", transport: "ws", errorContains: "--transport must be one of"},
		{name: "CA requires TLS", transport: "tcp", caFile: "test-ca.pem", errorContains: "requires --transport tls"},
		{name: "insecure requires TLS", transport: "udp", isInsecure: true, errorContains: "requires --transport tls"},
		{name: "conflicting TLS options", transport: "tls", caFile: "test-ca.pem", isInsecure: true, errorContains: "cannot be used together"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			configuration := Config{
				CallerRaw: "1001", CalleeRaw: "1002", HostRaw: "pbx.example.com:5061",
				LocalIP: "127.0.0.1", PCAP: "call.pcap", SSRCAudioRaw: "1234",
				Transport: scenario.transport, TLSCAFile: scenario.caFile, TLSInsecure: scenario.isInsecure,
			}
			err := configuration.ValidateRequired()
			if scenario.errorContains == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), scenario.errorContains) {
				t.Fatalf("error=%v, want containing %q", err, scenario.errorContains)
			}
		})
	}
}
