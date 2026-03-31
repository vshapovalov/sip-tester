package netutil

import (
	"net"
	"strings"
	"testing"
)

func TestResolveSIPTarget_PrefersMatchingFamily(t *testing.T) {
	lookup := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::5"), net.ParseIP("192.0.2.20")}, nil
	}

	gotV4, err := resolveSIPTargetWithLookup("sip.example.com", 5060, IPFamilyV4, lookup)
	if err != nil {
		t.Fatalf("v4 resolve failed: %v", err)
	}
	if gotV4.RemoteIP.String() != "192.0.2.20" {
		t.Fatalf("v4 picked %s", gotV4.RemoteIP.String())
	}

	gotV6, err := resolveSIPTargetWithLookup("sip.example.com", 5060, IPFamilyV6, lookup)
	if err != nil {
		t.Fatalf("v6 resolve failed: %v", err)
	}
	if gotV6.RemoteIP.String() != "2001:db8::5" {
		t.Fatalf("v6 picked %s", gotV6.RemoteIP.String())
	}
}

func TestResolveSIPTarget_NoMatchingFamily(t *testing.T) {
	lookup := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::5")}, nil
	}
	_, err := resolveSIPTargetWithLookup("sip.example.com", 5060, IPFamilyV4, lookup)
	if err == nil || !strings.Contains(err.Error(), "has no IPv4 address") {
		t.Fatalf("expected IPv4 mismatch error, got %v", err)
	}
}

func TestResolveSIPTarget_LiteralMismatch(t *testing.T) {
	_, err := resolveSIPTargetWithLookup("2001:db8::10", 5060, IPFamilyV4, func(string) ([]net.IP, error) {
		t.Fatal("lookup should not be called for literal IP")
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "host literal IP family does not match local-ip family") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSIPTarget_RemoteAddrFormatting(t *testing.T) {
	v4 := buildResolvedTarget("192.0.2.50", 5060, net.ParseIP("192.0.2.50"), IPFamilyV4)
	if v4.RemoteAddr != "192.0.2.50:5060" {
		t.Fatalf("unexpected v4 remote addr: %s", v4.RemoteAddr)
	}

	v6 := buildResolvedTarget("2001:db8::50", 5060, net.ParseIP("2001:db8::50"), IPFamilyV6)
	if v6.RemoteAddr != "[2001:db8::50]:5060" {
		t.Fatalf("unexpected v6 remote addr: %s", v6.RemoteAddr)
	}
}
