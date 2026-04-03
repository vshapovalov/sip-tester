package sipclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/netutil"
)

func TestRegister_RetriesWithDigestAuth(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		n, addr, _ := server.ReadFromUDP(buf)
		req1, _, _ := sip.ParseMessage(buf[:n])
		if req1 == nil || req1.Method != "REGISTER" {
			return
		}
		resp401 := &sip.Response{StatusCode: 401, Reason: "Unauthorized", Headers: map[string]string{
			"Via": req1.Headers["Via"], "From": req1.Headers["From"], "To": req1.Headers["To"], "Call-ID": req1.Headers["Call-ID"], "CSeq": req1.Headers["CSeq"],
			"WWW-Authenticate": `Digest realm="pbx", nonce="n1", qop="auth"`,
		}}
		_, _ = server.WriteToUDP(sip.BuildResponse(resp401), addr)

		n, addr, _ = server.ReadFromUDP(buf)
		req2, _, _ := sip.ParseMessage(buf[:n])
		if req2 == nil || !strings.Contains(req2.Headers["Authorization"], "Digest") {
			return
		}
		resp200 := &sip.Response{StatusCode: 200, Reason: "OK", Headers: map[string]string{
			"Via": req2.Headers["Via"], "From": req2.Headers["From"], "To": req2.Headers["To"], "Call-ID": req2.Headers["Call-ID"], "CSeq": req2.Headers["CSeq"],
		}}
		_, _ = server.WriteToUDP(sip.BuildResponse(resp200), addr)
	}()

	target := netutil.ResolvedTarget{Hostname: "127.0.0.1", RemoteIP: net.ParseIP("127.0.0.1"), RemoteAddr: server.LocalAddr().String()}
	c, err := NewClient(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, target, "1001", "secret")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Register(ctx, "sip:1001@example.com", "sip:1001@127.0.0.1:5060", 300); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	<-done
}
