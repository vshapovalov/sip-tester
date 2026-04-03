package sipclient

import (
	"net"
	"testing"
)

func TestBuildRegisterContactIPv4(t *testing.T) {
	contact, err := BuildRegisterContact("sip:159755@example.com", &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5060})
	if err != nil {
		t.Fatalf("BuildRegisterContact error: %v", err)
	}
	if contact != "sip:159755@192.0.2.10:5060" {
		t.Fatalf("contact=%q", contact)
	}
}

func TestBuildRegisterContactIPv6(t *testing.T) {
	contact, err := BuildRegisterContact("sip:159755@example.com", &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5060})
	if err != nil {
		t.Fatalf("BuildRegisterContact error: %v", err)
	}
	if contact != "sip:159755@[2001:db8::10]:5060" {
		t.Fatalf("contact=%q", contact)
	}
}
