package sipclient

import (
	"net"
	"reflect"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestInviteResultFromResponse_BuildsDialogStateWithRecordRoute(t *testing.T) {
	resp := &sip.Response{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string]string{
			"From":         "<sip:alice@example.com>;tag=local123",
			"To":           "<sip:bob@example.net>;tag=remote456",
			"Call-ID":      "call-1",
			"Contact":      "<sip:bob@192.0.2.20:5080;transport=udp>",
			"Record-Route": "<sip:edge1.example.net;lr>, <sip:core1.example.net;lr>",
		},
		Body: sampleSDPAnswer(),
	}

	res, err := inviteResultFromResponse(resp)
	if err != nil {
		t.Fatalf("inviteResultFromResponse() error = %v", err)
	}

	if got, want := res.RemoteTarget, "sip:bob@192.0.2.20:5080;transport=udp"; got != want {
		t.Fatalf("remote target = %q, want %q", got, want)
	}
	if got, want := res.RemoteTag, "remote456"; got != want {
		t.Fatalf("remote tag = %q, want %q", got, want)
	}
	wantRouteSet := []string{"<sip:core1.example.net;lr>", "<sip:edge1.example.net;lr>"}
	if !reflect.DeepEqual(res.RouteSet, wantRouteSet) {
		t.Fatalf("route set = %#v, want %#v", res.RouteSet, wantRouteSet)
	}
}

func TestBuildACK_UsesRemoteTargetAndRouteSet(t *testing.T) {
	c := testClientForRouting()
	res := InviteResult{
		ToHeader:     "<sip:bob@example.net>;tag=rtag1",
		RemoteTarget: "sip:bob@192.0.2.40:5080",
		RouteSet:     []string{"<sip:proxy2.example.net;lr>", "<sip:proxy1.example.net;lr>"},
	}

	ack := c.buildACK("sip:alice@example.com", res)
	if got, want := ack.URI, "sip:bob@192.0.2.40:5080"; got != want {
		t.Fatalf("ACK URI = %q, want %q", got, want)
	}
	if got, want := ack.Headers["Route"], "<sip:proxy2.example.net;lr>, <sip:proxy1.example.net;lr>"; got != want {
		t.Fatalf("ACK Route = %q, want %q", got, want)
	}
}

func TestBuildInDialogRequest_UsesRemoteTargetAndRouteSet(t *testing.T) {
	c := testClientForRouting()
	c.cseq = 2
	d := &Dialog{
		client:       c,
		fromURI:      "sip:alice@example.com",
		remoteTo:     "<sip:bob@example.net>;tag=rtag1",
		remoteTag:    "rtag1",
		remoteTarget: "sip:bob@192.0.2.41:5066",
		routeSet:     []string{"<sip:proxy.example.net;lr>"},
	}

	req := d.buildInDialogRequest("BYE", "")
	if got, want := req.URI, "sip:bob@192.0.2.41:5066"; got != want {
		t.Fatalf("BYE URI = %q, want %q", got, want)
	}
	if got, want := req.Headers["Route"], "<sip:proxy.example.net;lr>"; got != want {
		t.Fatalf("BYE Route = %q, want %q", got, want)
	}
	if got, want := req.Headers["CSeq"], "2 BYE"; got != want {
		t.Fatalf("BYE CSeq = %q, want %q", got, want)
	}
}

func TestBuildRouteSetForUAC_NoRecordRoute(t *testing.T) {
	got := buildRouteSetForUAC(nil)
	if got != nil {
		t.Fatalf("route set = %#v, want nil", got)
	}
}

func TestBuildRouteSetForUAC_OneRecordRoute(t *testing.T) {
	got := buildRouteSetForUAC([]string{"<sip:proxy1.example.net;lr>"})
	want := []string{"<sip:proxy1.example.net;lr>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route set = %#v, want %#v", got, want)
	}
}

func TestBuildRouteSetForUAC_MultipleRecordRoute(t *testing.T) {
	got := buildRouteSetForUAC([]string{"<sip:proxy1.example.net;lr>", "<sip:proxy2.example.net;lr>"})
	want := []string{"<sip:proxy2.example.net;lr>", "<sip:proxy1.example.net;lr>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route set = %#v, want %#v", got, want)
	}
}

func TestBuildRouteSetForUAS_PreservesOrder(t *testing.T) {
	got := buildRouteSetForUAS([]string{"<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"})
	want := []string{"<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route set = %#v, want %#v", got, want)
	}
}

func TestInboundBYE_UsesRemoteTargetAndUASRoutes(t *testing.T) {
	c := testClientForRouting()
	c.cseq = 4
	d := &InboundDialog{
		client:       c,
		fromURI:      "sip:alice@example.com",
		localTag:     "local123",
		remoteTo:     "<sip:bob@example.net>;tag=remote456",
		callID:       "call-1",
		remoteTarget: "sip:bob@192.0.2.55:5090",
		routeSet:     []string{"<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"},
	}

	req := d.buildByeRequest()
	if got, want := req.URI, "sip:bob@192.0.2.55:5090"; got != want {
		t.Fatalf("BYE URI = %q, want %q", got, want)
	}
	if got, want := req.Headers["Route"], "<sip:edge.example.net;lr>, <sip:core.example.net;lr>"; got != want {
		t.Fatalf("BYE Route = %q, want %q", got, want)
	}
}

func TestDialogMatchesDialog_ForIncomingINFO(t *testing.T) {
	c := testClientForRouting()
	d := &Dialog{
		client:    c,
		remoteTag: "remote456",
	}
	if !d.matchesDialog("call-1", "<sip:bob@example.net>;tag=remote456", "<sip:alice@example.com>;tag=local123") {
		t.Fatalf("expected dialog match for INFO")
	}
	if d.matchesDialog("call-2", "<sip:bob@example.net>;tag=remote456", "<sip:alice@example.com>;tag=local123") {
		t.Fatalf("did not expect match with wrong Call-ID")
	}
}

func testClientForRouting() *Client {
	return &Client{
		localAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5062},
		callID:    "call-1",
		localTag:  "local123",
		cseq:      1,
	}
}

func sampleSDPAnswer() string {
	return "v=0\r\n" +
		"o=- 1 1 IN IP4 192.0.2.20\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.20\r\n" +
		"t=0 0\r\n" +
		"m=audio 4000 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"
}
