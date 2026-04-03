package sip

import (
	"strings"
	"testing"
)

func TestParseMessage_PreservesRepeatedViaHeaders(t *testing.T) {
	raw := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP edge.example.net;branch=z9hG4bK-1\r\n" +
		"Via: SIP/2.0/UDP core.example.net;branch=z9hG4bK-2\r\n" +
		"From: <sip:alice@example.com>;tag=a\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: call-1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"

	req, _, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	vias := req.HeaderValues("Via")
	if len(vias) != 2 {
		t.Fatalf("Via count = %d, want 2", len(vias))
	}
	if vias[0] != "SIP/2.0/UDP edge.example.net;branch=z9hG4bK-1" || vias[1] != "SIP/2.0/UDP core.example.net;branch=z9hG4bK-2" {
		t.Fatalf("Via values = %#v", vias)
	}
}

func TestBuildResponse_PreservesRepeatedViaAndRecordRoute(t *testing.T) {
	resp := &Response{
		StatusCode: 180,
		Reason:     "Ringing",
		HeaderFields: []Header{
			{Name: "Via", Value: "SIP/2.0/UDP edge.example.net;branch=z9hG4bK-1"},
			{Name: "Via", Value: "SIP/2.0/UDP core.example.net;branch=z9hG4bK-2"},
			{Name: "Record-Route", Value: "<sip:edge.example.net;lr>"},
			{Name: "Record-Route", Value: "<sip:core.example.net;lr>"},
		},
	}

	built := string(BuildResponse(resp))
	if strings.Count(built, "\r\nVia: ") != 2 {
		t.Fatalf("expected 2 Via headers, got message:\n%s", built)
	}
	if strings.Count(built, "\r\nRecord-Route: ") != 2 {
		t.Fatalf("expected 2 Record-Route headers, got message:\n%s", built)
	}
	if !strings.Contains(built, "Via: SIP/2.0/UDP edge.example.net;branch=z9hG4bK-1\r\nVia: SIP/2.0/UDP core.example.net;branch=z9hG4bK-2") {
		t.Fatalf("Via ordering not preserved:\n%s", built)
	}
}

func TestParseMessage_PreservesRepeatedRecordRouteHeaders(t *testing.T) {
	raw := "SIP/2.0 200 OK\r\n" +
		"Record-Route: <sip:edge.example.net;lr>\r\n" +
		"Record-Route: <sip:core.example.net;lr>\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, resp, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	routes := resp.HeaderValues("Record-Route")
	if len(routes) != 2 {
		t.Fatalf("Record-Route count = %d, want 2", len(routes))
	}
	if routes[0] != "<sip:edge.example.net;lr>" || routes[1] != "<sip:core.example.net;lr>" {
		t.Fatalf("Record-Route values = %#v", routes)
	}
}
