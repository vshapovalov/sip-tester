package sipclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

type hangupDialog interface {
	HandleIncomingRequest(context.Context) (string, error)
	Bye(context.Context) error
}

func TestReinviteHandlesRemoteBYEWhileWaitingForResponse(t *testing.T) {
	server, client, call := newHangupDialog(t, "inbound")
	dialog := call.(*InboundDialog)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := dialog.Reinvite(ctx, sampleSDPAnswer())
		finished <- err
	}()
	reinvite := readHangupRequest(t, server)
	if reinvite.Method != "INVITE" {
		t.Fatalf("expected re-INVITE, got %s", reinvite.Method)
	}
	sendRequestToClient(t, server, client.LocalAddr(), remoteHangupRequest("BYE"))
	response := readResponseFromServer(t, server)
	if response.StatusCode != 200 || response.GetHeader("CSeq") != "42 BYE" {
		t.Fatalf("BYE response during re-INVITE: %+v", response)
	}
	if err := <-finished; err == nil || !strings.Contains(err.Error(), "remote BYE") {
		t.Fatalf("expected remote hangup result, got %v", err)
	}
	if err := dialog.Bye(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireNoHangupPacket(t, server)
}

func TestReinviteCancellationInterruptsResponseWait(t *testing.T) {
	server, _, call := newHangupDialog(t, "inbound")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := call.(*InboundDialog).Reinvite(ctx, sampleSDPAnswer())
		finished <- err
	}()
	readHangupRequest(t, server)
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt pending re-INVITE read")
	}
}

func TestDialogRemoteBYEAcknowledgedAndSuppressesLocalBYE(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			server, client, dialog := newHangupDialog(t, direction)
			request := remoteHangupRequest("BYE")
			sendRequestToClient(t, server, client.LocalAddr(), request)
			method, err := dialog.HandleIncomingRequest(context.Background())
			if err != nil || method != "BYE" {
				t.Fatalf("handle BYE: method=%q error=%v", method, err)
			}
			response := readResponseFromServer(t, server)
			if response.StatusCode != 200 || response.GetHeader("CSeq") != "42 BYE" || response.GetHeader("Call-ID") != "hangup-call" {
				t.Fatalf("incorrect BYE response: %+v", response)
			}
			if err := dialog.Bye(context.Background()); err != nil {
				t.Fatalf("already ended dialog: %v", err)
			}
			requireNoHangupPacket(t, server)
		})
	}
}

func TestDialogBYEHandlesCrossedBYEAndWaitsForMatchingResponse(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			server, client, dialog := newHangupDialog(t, direction)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- dialog.Bye(ctx) }()
			bye := readHangupRequest(t, server)
			if bye.Method != "BYE" {
				t.Fatalf("expected BYE, got %s", bye.Method)
			}
			sendRequestToClient(t, server, client.LocalAddr(), remoteHangupRequest("BYE"))
			response := readResponseFromServer(t, server)
			if response.StatusCode != 200 || response.GetHeader("CSeq") != "42 BYE" {
				t.Fatalf("crossed BYE response: %+v", response)
			}
			for _, unrelated := range []struct {
				callID, cseq string
				status       int
			}{
				{"other-call", bye.GetHeader("CSeq"), 200},
				{"hangup-call", "99 INFO", 200},
				{"hangup-call", bye.GetHeader("CSeq"), 100},
			} {
				sendHangupResponse(t, server, client, unrelated.callID, unrelated.cseq, unrelated.status)
			}
			if _, err := server.WriteToUDP([]byte("invalid SIP packet"), client.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			foreignBYE := remoteHangupRequest("BYE")
			foreignBYE.Headers["Call-ID"] = "other-call"
			sendRequestToClient(t, server, client.LocalAddr(), foreignBYE)
			sendRequestToClient(t, server, client.LocalAddr(), remoteHangupRequest("INFO"))
			infoResponse := readResponseFromServer(t, server)
			if infoResponse.GetHeader("CSeq") != "42 INFO" {
				t.Fatalf("expected INFO response while awaiting own BYE response, got %+v", infoResponse)
			}
			select {
			case err := <-finished:
				t.Fatalf("BYE completed on an unrelated response: %v", err)
			default:
			}
			sendHangupResponse(t, server, client, bye.GetHeader("Call-ID"), bye.GetHeader("CSeq"), 200)
			if err := <-finished; err != nil {
				t.Fatalf("BYE transaction failed: %v", err)
			}
		})
	}
}

func TestDialogIgnoresUnrelatedBYEWithoutEndingCall(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			server, client, dialog := newHangupDialog(t, direction)
			for _, changedHeader := range []string{"Call-ID", "From", "To"} {
				request := remoteHangupRequest("BYE")
				request.Headers[changedHeader] = "wrong-dialog"
				sendRequestToClient(t, server, client.LocalAddr(), request)
				if _, err := dialog.HandleIncomingRequest(context.Background()); !errors.Is(err, ErrIgnoredDialogMessage) {
					t.Fatalf("mismatched %s: %v", changedHeader, err)
				}
			}
			sendRequestToClient(t, server, client.LocalAddr(), remoteHangupRequest("OPTIONS"))
			if _, err := dialog.HandleIncomingRequest(context.Background()); !errors.Is(err, ErrIgnoredDialogMessage) {
				t.Fatalf("unsupported request: %v", err)
			}
			sendHangupResponse(t, server, client, "hangup-call", "1 INVITE", 200)
			if _, err := dialog.HandleIncomingRequest(context.Background()); !errors.Is(err, ErrIgnoredDialogMessage) {
				t.Fatalf("unexpected response: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- dialog.Bye(ctx) }()
			bye := readHangupRequest(t, server)
			sendHangupResponse(t, server, client, bye.GetHeader("Call-ID"), bye.GetHeader("CSeq"), 200)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialogBYEReportsRejectionTimeoutAndClosedTransport(t *testing.T) {
	for _, scenario := range []string{"rejected", "timeout", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			server, client, dialog := newHangupDialog(t, "outbound")
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if scenario == "closed" {
				_ = client.Close()
			}
			finished := make(chan error, 1)
			go func() { finished <- dialog.Bye(ctx) }()
			if scenario != "closed" {
				bye := readHangupRequest(t, server)
				if scenario == "rejected" {
					sendHangupResponse(t, server, client, bye.GetHeader("Call-ID"), bye.GetHeader("CSeq"), 500)
				}
			}
			err := <-finished
			expectedError := map[string]string{"rejected": "BYE failed with 500", "timeout": "wait BYE response", "closed": "send BYE"}[scenario]
			if err == nil || !strings.Contains(err.Error(), expectedError) {
				t.Fatalf("expected %s error, got %v", scenario, err)
			}
		})
	}
}

func TestDialogRequestReportsCancellationAndClosedTransport(t *testing.T) {
	_, client, dialog := newHangupDialog(t, "outbound")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialog.HandleIncomingRequest(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: %v", err)
	}
	_ = client.Close()
	if _, err := dialog.HandleIncomingRequest(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
}

func newHangupDialog(t *testing.T, direction string) (*net.UDPConn, *Client, hangupDialog) {
	t.Helper()
	server := mustListenUDP(t)
	t.Cleanup(func() { _ = server.Close() })
	client := mustNewClientForServer(t, server)
	t.Cleanup(func() { _ = client.Close() })
	client.callID = "hangup-call"
	client.localTag = "local"
	if direction == "outbound" {
		return server, client, &Dialog{
			client: client, fromURI: "sip:1001@example.com", remoteTo: "<sip:1002@example.com>;tag=remote",
			remoteTag: "remote", remoteTarget: "sip:1002@" + server.LocalAddr().String(),
		}
	}
	return server, client, &InboundDialog{
		client: client, fromURI: "sip:1001@example.com", remoteTo: "<sip:1002@example.com>;tag=remote",
		callID: "hangup-call", localTag: "local", remoteTag: "remote", remoteTarget: "sip:1002@" + server.LocalAddr().String(),
	}
}

func remoteHangupRequest(method string) *sip.Request {
	return &sip.Request{Method: method, URI: "sip:1001@example.com", Headers: map[string]string{
		"Via":  "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-remote",
		"From": "<sip:1002@example.com>;tag=remote", "To": "<sip:1001@example.com>;tag=local",
		"Call-ID": "hangup-call", "CSeq": "42 " + method,
	}}
}

func readHangupRequest(t *testing.T, server *net.UDPConn) *sip.Request {
	t.Helper()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	length, _, err := server.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := sip.ParseMessage(packet[:length])
	if err != nil || request == nil {
		t.Fatalf("expected SIP request: %s (%v)", packet[:length], err)
	}
	return request
}

func sendHangupResponse(t *testing.T, server *net.UDPConn, client *Client, callID, cseq string, status int) {
	t.Helper()
	response := &sip.Response{StatusCode: status, Reason: "Test", Headers: map[string]string{
		"Via": "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test", "Call-ID": callID, "CSeq": cseq,
		"From": "<sip:1001@example.com>;tag=local", "To": "<sip:1002@example.com>;tag=remote",
	}}
	if _, err := server.WriteToUDP(sip.BuildResponse(response), client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
}

func requireNoHangupPacket(t *testing.T, server *net.UDPConn) {
	t.Helper()
	if err := server.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	length, _, err := server.ReadFromUDP(packet)
	if err == nil {
		t.Fatalf("unexpected SIP packet: %s", packet[:length])
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatal(err)
	}
}
