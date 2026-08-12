package sipclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/netutil"
)

func TestSendInviteWithOptions_CancelsAuthenticatedPendingInvite(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer server.Close()

	serverError := make(chan error, 1)
	go func() {
		serverError <- serveAuthenticatedInviteCancellation(server)
	}()

	target := netutil.ResolvedTarget{
		Hostname:   "example.test",
		Port:       5060,
		RemoteIP:   net.ParseIP("127.0.0.1"),
		RemoteAddr: server.LocalAddr().String(),
	}
	client, err := NewClient(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, target, "1001", "secret", "test-ua")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.SendInviteWithOptions(
		ctx,
		"sip:1001@example.test",
		"sip:1002@example.test",
		sampleSDPAnswer(),
		InviteOptions{
			Headers:     map[string]string{"X-Speech-ID": "repro-cancel"},
			CancelAfter: 50 * time.Millisecond,
		},
		nil,
	)
	if !errors.Is(err, ErrInviteCancelled) {
		t.Fatalf("SendInviteWithOptions error=%v, want ErrInviteCancelled", err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func serveAuthenticatedInviteCancellation(server *net.UDPConn) error {
	firstInvite, callerAddress, err := readSIPRequest(server)
	if err != nil {
		return err
	}
	if firstInvite.Method != "INVITE" {
		return fmt.Errorf("first method=%s, want INVITE", firstInvite.Method)
	}
	if err := writeSIPResponse(server, callerAddress, firstInvite, 407, "Proxy Authentication Required", map[string]string{
		"Proxy-Authenticate": `Digest realm="proxy", nonce="n1", qop="auth"`,
	}); err != nil {
		return err
	}

	authenticatedInvite, callerAddress, err := readSIPRequest(server)
	if err != nil {
		return err
	}
	if authenticatedInvite.Method != "INVITE" || !strings.Contains(authenticatedInvite.GetHeader("Proxy-Authorization"), "Digest") {
		return fmt.Errorf("authenticated request is not an authorized INVITE")
	}
	if got := authenticatedInvite.GetHeader("X-Speech-ID"); got != "repro-cancel" {
		return fmt.Errorf("X-Speech-ID=%q", got)
	}
	if err := writeSIPResponse(server, callerAddress, authenticatedInvite, 100, "Trying", nil); err != nil {
		return err
	}

	cancelRequest, callerAddress, err := readSIPRequest(server)
	if err != nil {
		return err
	}
	if cancelRequest.Method != "CANCEL" {
		return fmt.Errorf("method=%s, want CANCEL", cancelRequest.Method)
	}
	for _, headerName := range []string{"Via", "From", "To", "Call-ID"} {
		if cancelRequest.GetHeader(headerName) != authenticatedInvite.GetHeader(headerName) {
			return fmt.Errorf("CANCEL %s=%q, want %q", headerName, cancelRequest.GetHeader(headerName), authenticatedInvite.GetHeader(headerName))
		}
	}
	if got, want := cancelRequest.GetHeader("CSeq"), strings.TrimSuffix(authenticatedInvite.GetHeader("CSeq"), "INVITE")+"CANCEL"; got != want {
		return fmt.Errorf("CANCEL CSeq=%q, want %q", got, want)
	}
	if cancelRequest.URI != authenticatedInvite.URI {
		return fmt.Errorf("CANCEL URI=%q, want %q", cancelRequest.URI, authenticatedInvite.URI)
	}
	if err := writeSIPResponse(server, callerAddress, cancelRequest, 200, "OK", nil); err != nil {
		return err
	}
	return writeSIPResponse(server, callerAddress, authenticatedInvite, 487, "Request Terminated", nil)
}

func readSIPRequest(server *net.UDPConn) (*sip.Request, *net.UDPAddr, error) {
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return nil, nil, err
	}
	buffer := make([]byte, 64*1024)
	readCount, address, err := server.ReadFromUDP(buffer)
	if err != nil {
		return nil, nil, err
	}
	request, _, err := sip.ParseMessage(buffer[:readCount])
	if err != nil {
		return nil, nil, err
	}
	if request == nil {
		return nil, nil, fmt.Errorf("message is not a SIP request")
	}
	return request, address, nil
}

func writeSIPResponse(server *net.UDPConn, address *net.UDPAddr, request *sip.Request, status int, reason string, extraHeaders map[string]string) error {
	headers := map[string]string{
		"Via":     request.GetHeader("Via"),
		"From":    request.GetHeader("From"),
		"To":      request.GetHeader("To"),
		"Call-ID": request.GetHeader("Call-ID"),
		"CSeq":    request.GetHeader("CSeq"),
	}
	for name, headerValue := range extraHeaders {
		headers[name] = headerValue
	}
	_, err := server.WriteToUDP(sip.BuildResponse(&sip.Response{StatusCode: status, Reason: reason, Headers: headers}), address)
	return err
}
