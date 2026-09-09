package config

import "testing"

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
}
