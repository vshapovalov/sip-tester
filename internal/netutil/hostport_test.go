package netutil

import "testing"

func TestParseHostPortIPv6(t *testing.T) {
	host, port, err := ParseHostPort("[2001:db8::1]:5060")
	if err != nil {
		t.Fatalf("ParseHostPort returned error: %v", err)
	}
	if host != "2001:db8::1" {
		t.Fatalf("host = %q, want %q", host, "2001:db8::1")
	}
	if port != 5060 {
		t.Fatalf("port = %d, want 5060", port)
	}
}
