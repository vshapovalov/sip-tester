package sipclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/netutil"
)

const streamTestSDP = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 12000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\nm=video 12002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"

func TestStreamClientRegistersAndCompletesOutboundDialog(t *testing.T) {
	for _, protocol := range []string{"tcp", "tls"} {
		t.Run(protocol, func(t *testing.T) {
			client, peer := newStreamTestClient(t, protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			completed := make(chan error, 1)
			go func() {
				contact, err := client.Contact("sip:1001@example.com")
				if err == nil {
					err = client.Register(ctx, "sip:1001@example.com", contact, 60)
				}
				if err != nil {
					completed <- err
					return
				}
				dialog, err := client.Invite(ctx, "sip:1001@example.com", "sip:1002@example.com", streamTestSDP)
				if err == nil {
					err = dialog.Info(ctx, InfoPayload{ContentType: "application/dtmf-relay", Body: "Signal=1\r\nDuration=160\r\n"})
				}
				if err == nil {
					err = dialog.Bye(ctx)
				}
				completed <- err
			}()
			for _, method := range []string{"REGISTER", "REGISTER", "INVITE", "ACK", "INFO", "BYE"} {
				request := readStreamRequest(t, peer)
				if request.Method != method {
					t.Fatalf("method = %s, want %s", request.Method, method)
				}
				if !strings.HasPrefix(request.GetHeader("Via"), "SIP/2.0/"+strings.ToUpper(protocol)+" ") {
					t.Fatal(request.GetHeader("Via"))
				}
				if method == "REGISTER" || method == "INVITE" || method == "ACK" {
					want := "<sip:1001@" + client.LocalAddr().String() + ";transport=" + protocol + ">"
					if request.GetHeader("Contact") != want {
						t.Fatalf("Contact = %s, want %s", request.GetHeader("Contact"), want)
					}
				}
				if method == "ACK" {
					continue
				}
				response := streamResponse(request)
				if method == "REGISTER" && request.GetHeader("Authorization") == "" {
					response.StatusCode = 401
					response.Reason = "Unauthorized"
					response.Headers["WWW-Authenticate"] = `Digest realm="example.com", nonce="test-nonce", algorithm=MD5, qop="auth"`
				}
				writeStreamPacket(t, peer, sip.BuildResponse(response))
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamClientVerifiesTLSCertificate(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	defer certificateServer.Close()
	trust := x509.NewCertPool()
	trust.AddCert(certificateServer.Certificate())
	for _, scenario := range []struct {
		name, hostname      string
		roots               *x509.CertPool
		insecure, wantError bool
	}{
		{"trusted self-signed", "example.com", trust, false, false},
		{"untrusted self-signed", "example.com", x509.NewCertPool(), false, true},
		{"wrong hostname", "wrong.example", trust, false, true},
		{"explicit insecure", "wrong.example", nil, true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				tls.Server(conn, certificateServer.TLS).Handshake()
			}()
			target := netutil.ResolvedTarget{Hostname: scenario.hostname, RemoteAddr: listener.Addr().String()}
			client, err := NewClientWithTransport(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, target, "", "", "test", TransportOptions{Protocol: "tls", TLSConfig: &tls.Config{RootCAs: scenario.roots, InsecureSkipVerify: scenario.insecure}})
			if client != nil {
				client.Close()
			}
			if (err != nil) != scenario.wantError {
				t.Fatalf("TLS error = %v", err)
			}
			<-finished
		})
	}
}

func TestStreamClientAnswersAndRenegotiatesInboundDialog(t *testing.T) {
	for _, protocol := range []string{"tcp", "tls"} {
		t.Run(protocol, func(t *testing.T) {
			client, peer := newStreamTestClient(t, protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			completed := make(chan error, 1)
			go func() {
				invite, sender, err := client.WaitForInvite(ctx)
				if err != nil {
					completed <- err
					return
				}
				dialog, err := client.NewInboundDialog(invite, "sip:1001@example.com")
				if err == nil {
					err = dialog.SendInviteResponse(invite, sender, 200, "OK", streamTestSDP, "application/sdp")
				}
				if err == nil {
					err = dialog.WaitForACK(ctx)
				}
				if err == nil {
					var answer SDPAnswer
					answer, err = dialog.Reinvite(ctx, streamTestSDP)
					if err == nil && (len(answer.Media) != 2 || answer.Media[1].Type != "video") {
						err = fmt.Errorf("re-INVITE lost video: %+v", answer)
					}
				}
				if err == nil {
					_, err = dialog.HandleIncomingRequest(ctx)
				}
				if err == nil {
					err = dialog.Bye(ctx)
				}
				completed <- err
			}()
			invite := &sip.Request{Method: "INVITE", URI: "sip:1001@example.com", Headers: map[string]string{
				"Via":  "SIP/2.0/" + strings.ToUpper(protocol) + " " + peer.LocalAddr().String() + ";branch=z9hG4bK-stream",
				"From": "<sip:1002@example.com>;tag=remote", "To": "<sip:1001@example.com>",
				"Call-ID": "stream-inbound", "CSeq": "1 INVITE", "Contact": "<sip:1002@127.0.0.1:59999>", "Content-Type": "application/sdp",
			}, Body: streamTestSDP}
			writeStreamPacket(t, peer, sip.BuildRequest(invite))
			response := readStreamResponse(t, peer)
			wantContact := "<sip:1001@" + client.LocalAddr().String() + ";transport=" + protocol + ">"
			if response.StatusCode != 200 || response.GetHeader("Contact") != wantContact {
				t.Fatalf("answer = %+v", response)
			}
			invite.Method = "ACK"
			invite.Headers["CSeq"] = "1 ACK"
			invite.Headers["To"] = response.GetHeader("To")
			invite.Body = ""
			writeStreamPacket(t, peer, sip.BuildRequest(invite))
			reinvite := readStreamRequest(t, peer)
			if reinvite.Method != "INVITE" || reinvite.GetHeader("Contact") != wantContact || !strings.HasPrefix(reinvite.GetHeader("Via"), "SIP/2.0/"+strings.ToUpper(protocol)+" ") {
				t.Fatalf("re-INVITE = %+v", reinvite)
			}
			writeStreamPacket(t, peer, sip.BuildResponse(streamResponse(reinvite)))
			if ack := readStreamRequest(t, peer); ack.Method != "ACK" {
				t.Fatalf("received %s instead of ACK", ack.Method)
			}
			invite.Method = "INFO"
			invite.Headers["CSeq"] = "2 INFO"
			writeStreamPacket(t, peer, sip.BuildRequest(invite))
			if response := readStreamResponse(t, peer); response.StatusCode != 200 {
				t.Fatalf("INFO response %d", response.StatusCode)
			}
			bye := readStreamRequest(t, peer)
			if bye.Method != "BYE" || !strings.HasPrefix(bye.GetHeader("Via"), "SIP/2.0/"+strings.ToUpper(protocol)+" ") {
				t.Fatalf("BYE = %+v", bye)
			}
			writeStreamPacket(t, peer, sip.BuildResponse(streamResponse(bye)))
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func readStreamResponse(t *testing.T, peer *streamSocket) *sip.Response {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet := make([]byte, readBufferSize)
	length, _, err := peer.ReadFrom(packet)
	if err != nil {
		t.Fatal(err)
	}
	_, response, err := sip.ParseMessage(packet[:length])
	if err != nil || response == nil {
		t.Fatalf("read SIP response: %v %q", err, packet[:length])
	}
	return response
}

func newStreamTestClient(t *testing.T, protocol string) (*Client, *streamSocket) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	options := TransportOptions{Protocol: protocol}
	if protocol == "tls" {
		certificateServer := httptest.NewTLSServer(nil)
		t.Cleanup(certificateServer.Close)
		trust := x509.NewCertPool()
		trust.AddCert(certificateServer.Certificate())
		options.TLSConfig = &tls.Config{RootCAs: trust}
		listener = tls.NewListener(listener, certificateServer.TLS)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
			tlsConn.Handshake()
		}
		accepted <- conn
	}()
	address := listener.Addr().(*net.TCPAddr)
	target := netutil.ResolvedTarget{Hostname: "127.0.0.1", Port: uint16(address.Port), RemoteAddr: address.String()}
	client, err := NewClientWithTransport(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, target, "1001", "test-password", "test", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	conn := <-accepted
	if conn == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { conn.Close() })
	return client, &streamSocket{Conn: conn}
}

func readStreamRequest(t *testing.T, peer *streamSocket) *sip.Request {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet := make([]byte, readBufferSize)
	length, _, err := peer.ReadFrom(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := sip.ParseMessage(packet[:length])
	if err != nil || request == nil {
		t.Fatalf("read SIP request: %v %q", err, packet[:length])
	}
	return request
}

func writeStreamPacket(t *testing.T, peer *streamSocket, packet []byte) {
	t.Helper()
	if _, err := peer.WriteTo(packet, peer.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
}

func streamResponse(request *sip.Request) *sip.Response {
	headers := map[string]string{}
	for _, name := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
		headers[name] = request.GetHeader(name)
	}
	response := &sip.Response{StatusCode: 200, Reason: "OK", Headers: headers}
	if request.Method == "INVITE" {
		if !strings.Contains(headers["To"], ";tag=") {
			headers["To"] += ";tag=remote"
		}
		headers["Contact"] = "<sip:1002@127.0.0.1:59999>"
		headers["Content-Type"] = "application/sdp"
		response.Body = streamTestSDP
	}
	return response
}

func TestStreamClientRejectsUnsupportedTransport(t *testing.T) {
	client, err := NewClientWithTransport(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, netutil.ResolvedTarget{}, "", "", "", TransportOptions{Protocol: "ws"})
	if err == nil {
		client.Close()
		t.Fatal("unsupported transport accepted")
	}
}
