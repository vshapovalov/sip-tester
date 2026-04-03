package sipclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/netutil"
)

func TestInviteResponseToHeaderAddsLocalTag(t *testing.T) {
	d := &InboundDialog{fromURI: "sip:alice@example.com", localTag: "ltag1"}
	invite := &sip.Request{Headers: map[string]string{"To": "<sip:alice@example.com>"}}
	if got, want := d.inviteToWithLocalTag(invite), "<sip:alice@example.com>;tag=ltag1"; got != want {
		t.Fatalf("to header=%q, want %q", got, want)
	}
}

func TestSendInviteResponse_200IncludesContact(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	tests := []struct {
		name        string
		localURI    string
		localIP     string
		wantContact string
	}{
		{
			name:        "ipv4",
			localURI:    "sip:159755@example.com",
			localIP:     "192.0.2.10",
			wantContact: "<sip:159755@192.0.2.10:5060>",
		},
		{
			name:        "ipv6",
			localURI:    "sip:159755@example.com",
			localIP:     "2001:db8::10",
			wantContact: "<sip:159755@[2001:db8::10]:5060>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialog := &InboundDialog{
				client:   client,
				fromURI:  tt.localURI,
				localTag: "ltag",
			}
			dialog.client.localAddr = &net.UDPAddr{IP: net.ParseIP(tt.localIP), Port: 5060}

			invite := &sip.Request{
				Method: "INVITE",
				Headers: map[string]string{
					"Via":     "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-invite",
					"From":    "<sip:bob@example.net>;tag=rtag",
					"To":      "<sip:159755@example.com>",
					"Call-ID": "call-invite-contact",
					"CSeq":    "1 INVITE",
				},
			}
			if err := dialog.SendInviteResponse(invite, server.LocalAddr().(*net.UDPAddr), 200, "OK", "v=0", "application/sdp"); err != nil {
				t.Fatalf("SendInviteResponse() error = %v", err)
			}

			resp := readResponseFromServer(t, server)
			if got := resp.Headers["Contact"]; got != tt.wantContact {
				t.Fatalf("Contact header = %q, want %q", got, tt.wantContact)
			}
		})
	}
}

func TestSendInviteResponse_180DoesNotAddContact(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()
	dialog := &InboundDialog{
		client:   client,
		fromURI:  "sip:159755@example.com",
		localTag: "ltag",
	}
	dialog.client.localAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5060}

	invite := &sip.Request{
		Method: "INVITE",
		Headers: map[string]string{
			"Via":     "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-ringing",
			"From":    "<sip:bob@example.net>;tag=rtag",
			"To":      "<sip:159755@example.com>",
			"Call-ID": "call-ringing",
			"CSeq":    "1 INVITE",
		},
	}
	if err := dialog.SendInviteResponse(invite, server.LocalAddr().(*net.UDPAddr), 180, "Ringing", "", ""); err != nil {
		t.Fatalf("SendInviteResponse() error = %v", err)
	}

	resp := readResponseFromServer(t, server)
	if got := resp.Headers["Contact"]; got != "" {
		t.Fatalf("unexpected Contact in 180: %q", got)
	}
}

func TestSendInviteResponse_PropagatesAllViaAndRecordRoute(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	dialog := &InboundDialog{
		client:   client,
		fromURI:  "sip:alice@example.com",
		localTag: "ltag",
	}
	dialog.client.localAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5060}

	invite := &sip.Request{
		Method: "INVITE",
		Headers: map[string]string{
			"From":    "<sip:bob@example.net>;tag=rtag",
			"To":      "<sip:alice@example.com>",
			"Call-ID": "call-multi",
			"CSeq":    "1 INVITE",
		},
		HeaderFields: []sip.Header{
			{Name: "Via", Value: "SIP/2.0/UDP edge.example.net;branch=z9hG4bK-edge"},
			{Name: "Via", Value: "SIP/2.0/UDP core.example.net;branch=z9hG4bK-core"},
			{Name: "Record-Route", Value: "<sip:edge.example.net;lr>"},
			{Name: "Record-Route", Value: "<sip:core.example.net;lr>"},
			{Name: "From", Value: "<sip:bob@example.net>;tag=rtag"},
			{Name: "To", Value: "<sip:alice@example.com>"},
			{Name: "Call-ID", Value: "call-multi"},
			{Name: "CSeq", Value: "1 INVITE"},
			{Name: "Contact", Value: "<sip:bob@198.51.100.10:5070>"},
		},
	}

	if err := dialog.SendInviteResponse(invite, server.LocalAddr().(*net.UDPAddr), 180, "Ringing", "", ""); err != nil {
		t.Fatalf("SendInviteResponse(180) error = %v", err)
	}
	ringing := readResponseFromServer(t, server)
	if got, want := ringing.HeaderValues("Via"), []string{"SIP/2.0/UDP edge.example.net;branch=z9hG4bK-edge", "SIP/2.0/UDP core.example.net;branch=z9hG4bK-core"}; !equalStringSlices(got, want) {
		t.Fatalf("180 Via=%#v want %#v", got, want)
	}
	if got, want := ringing.HeaderValues("Record-Route"), []string{"<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"}; !equalStringSlices(got, want) {
		t.Fatalf("180 Record-Route=%#v want %#v", got, want)
	}
	if got := ringing.GetHeader("To"); got != "<sip:alice@example.com>;tag=ltag" {
		t.Fatalf("180 To=%q", got)
	}

	if err := dialog.SendInviteResponse(invite, server.LocalAddr().(*net.UDPAddr), 200, "OK", "v=0", "application/sdp"); err != nil {
		t.Fatalf("SendInviteResponse(200) error = %v", err)
	}
	ok := readResponseFromServer(t, server)
	if got, want := ok.HeaderValues("Via"), []string{"SIP/2.0/UDP edge.example.net;branch=z9hG4bK-edge", "SIP/2.0/UDP core.example.net;branch=z9hG4bK-core"}; !equalStringSlices(got, want) {
		t.Fatalf("200 Via=%#v want %#v", got, want)
	}
	if got, want := ok.HeaderValues("Record-Route"), []string{"<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"}; !equalStringSlices(got, want) {
		t.Fatalf("200 Record-Route=%#v want %#v", got, want)
	}
	if got := ok.GetHeader("Contact"); got == "" {
		t.Fatalf("200 Contact missing")
	}
}

func TestInboundDialogMatchesACKAndINFO(t *testing.T) {
	d := &InboundDialog{callID: "call-1", remoteTag: "rtag", localTag: "ltag"}
	ack := &sip.Request{Method: "ACK", Headers: map[string]string{
		"Call-ID": "call-1",
		"From":    "<sip:bob@example.net>;tag=rtag",
		"To":      "<sip:alice@example.com>;tag=ltag",
	}}
	if !d.matchesRequestDialog(ack) {
		t.Fatalf("expected ACK to match dialog")
	}
	info := &sip.Request{Method: "INFO", Headers: map[string]string{
		"Call-ID": "call-1",
		"From":    "<sip:bob@example.net>;tag=rtag",
		"To":      "<sip:alice@example.com>;tag=ltag",
	}}
	if !d.matchesRequestDialog(info) {
		t.Fatalf("expected INFO to match dialog")
	}
}

func TestWaitForACK_BlocksUntilMatchingACK(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	dialog := &InboundDialog{
		client:    client,
		callID:    "call-ack",
		remoteTag: "rtag",
		localTag:  "ltag",
	}

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done <- dialog.WaitForACK(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	sendRequestToClient(t, server, client.LocalAddr(), &sip.Request{
		Method: "ACK",
		URI:    "sip:alice@example.com",
		Headers: map[string]string{
			"Via":     "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-a",
			"From":    "<sip:bob@example.net>;tag=rtag",
			"To":      "<sip:alice@example.com>;tag=ltag",
			"Call-ID": "call-ack",
			"CSeq":    "1 ACK",
		},
	})

	if err := <-done; err != nil {
		t.Fatalf("WaitForACK() error = %v", err)
	}
}

func TestHandleIncomingRequest_INFOGets200OK(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	dialog := &InboundDialog{
		client:    client,
		callID:    "call-info",
		remoteTag: "rtag",
		localTag:  "ltag",
	}

	result := make(chan string, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		method, err := dialog.HandleIncomingRequest(ctx)
		if err != nil {
			result <- "error:" + err.Error()
			return
		}
		result <- method
	}()

	req := &sip.Request{
		Method: "INFO",
		URI:    "sip:alice@example.com",
		Headers: map[string]string{
			"Via":          "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-info",
			"From":         "<sip:bob@example.net>;tag=rtag",
			"To":           "<sip:alice@example.com>;tag=ltag",
			"Call-ID":      "call-info",
			"CSeq":         "2 INFO",
			"Content-Type": "application/dtmf-relay",
		},
		Body: "Signal=1\r\nDuration=160",
	}
	payload := sip.BuildRequest(req)
	if _, err := server.WriteToUDP(payload, client.LocalAddr()); err != nil {
		t.Fatalf("send INFO to client: %v", err)
	}

	resp := readResponseFromServer(t, server)
	if resp.StatusCode != 200 {
		t.Fatalf("INFO response status = %d", resp.StatusCode)
	}
	if got := <-result; got != "INFO" {
		t.Fatalf("HandleIncomingRequest()=%q", got)
	}
}

func TestInboundDialogBye_WaitsFor200OK(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	dialog := &InboundDialog{
		client:       client,
		fromURI:      "sip:alice@example.com",
		callID:       "call-bye",
		localTag:     "ltag",
		remoteTo:     "<sip:bob@example.net>;tag=rtag",
		remoteTarget: "sip:bob@example.net",
	}

	done := make(chan error, 1)
	go func() {
		req, addr := readRequestFromServer(t, server)
		if req.Method != "BYE" {
			done <- context.Canceled
			return
		}
		resp := &sip.Response{StatusCode: 200, Reason: "OK", Headers: map[string]string{
			"Via": req.Headers["Via"], "From": req.Headers["From"], "To": req.Headers["To"], "Call-ID": req.Headers["Call-ID"], "CSeq": req.Headers["CSeq"],
		}}
		_, err := server.WriteToUDP(sip.BuildResponse(resp), addr)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dialog.Bye(ctx); err != nil {
		t.Fatalf("Bye() error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handling error = %v", err)
	}
}

func TestWaitForInvite_DoesNotChallengeUnauthenticatedInvite(t *testing.T) {
	server := mustListenUDP(t)
	defer server.Close()

	client := mustNewClientForServer(t, server)
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		req, _, err := client.WaitForInvite(ctx)
		if err != nil {
			done <- err
			return
		}
		if req.Headers["Authorization"] != "" || req.Headers["Proxy-Authorization"] != "" {
			done <- nil
			return
		}
		done <- nil
	}()

	sendRequestToClient(t, server, client.LocalAddr(), &sip.Request{
		Method: "INVITE",
		URI:    "sip:alice@example.com",
		Headers: map[string]string{
			"Via":     "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-inbound-no-auth",
			"From":    "<sip:bob@example.net>;tag=rtag",
			"To":      "<sip:alice@example.com>",
			"Call-ID": "call-no-auth",
			"CSeq":    "1 INVITE",
			"Contact": "<sip:bob@example.net>",
		},
		Body: "v=0",
	})

	if err := <-done; err != nil {
		t.Fatalf("WaitForInvite() error = %v", err)
	}

	// WaitForInvite must not emit a challenge response for inbound-mode initial INVITEs.
	_ = server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, readBufferSize)
	n, _, err := server.ReadFromUDP(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return
	}
	if err != nil {
		t.Fatalf("read possible challenge response: %v", err)
	}
	_, resp, parseErr := sip.ParseMessage(buf[:n])
	if parseErr != nil || resp == nil {
		t.Fatalf("unexpected outbound packet after INVITE: parseErr=%v", parseErr)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 407 {
		t.Fatalf("unexpected auth challenge response %d", resp.StatusCode)
	}
	t.Fatalf("unexpected response to initial inbound INVITE: %d %s", resp.StatusCode, resp.Reason)
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return conn
}

func mustNewClientForServer(t *testing.T, server *net.UDPConn) *Client {
	t.Helper()
	target := netutil.ResolvedTarget{
		Hostname:   "127.0.0.1",
		RemoteIP:   net.ParseIP("127.0.0.1"),
		RemoteAddr: server.LocalAddr().String(),
	}
	client, err := NewClient(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, target, "", "")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func sendRequestToClient(t *testing.T, server *net.UDPConn, dst *net.UDPAddr, req *sip.Request) {
	t.Helper()
	if _, err := server.WriteToUDP(sip.BuildRequest(req), dst); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func readResponseFromServer(t *testing.T, server *net.UDPConn) *sip.Response {
	t.Helper()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, readBufferSize)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, resp, err := sip.ParseMessage(buf[:n])
	if err != nil || resp == nil {
		t.Fatalf("parse response err=%v", err)
	}
	return resp
}

func readRequestFromServer(t *testing.T, server *net.UDPConn) (*sip.Request, *net.UDPAddr) {
	t.Helper()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, readBufferSize)
	n, addr, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	req, _, err := sip.ParseMessage(buf[:n])
	if err != nil || req == nil {
		t.Fatalf("parse request err=%v", err)
	}
	return req, addr
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
