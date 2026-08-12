package app

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
	"sip-tester/internal/replay"
	"sip-tester/internal/sdp"
	"sip-tester/internal/sipclient"
)

func TestOutboundInviteOptionsFromConfig(t *testing.T) {
	options := outboundInviteOptions(&config.Config{
		Headers:     map[string]string{"X-Speech-ID": "repro"},
		CancelAfter: 2 * time.Second,
	})
	if options.Headers["X-Speech-ID"] != "repro" {
		t.Fatalf("headers=%v", options.Headers)
	}
	if options.CancelAfter != 2*time.Second {
		t.Fatalf("cancel-after=%s", options.CancelAfter)
	}
}

func TestInboundAnswerDelayUsesDefaultAndOverride(t *testing.T) {
	if got := inboundAnswerDelay(&config.Config{}); got != 3*time.Second {
		t.Fatalf("default answer delay=%s", got)
	}
	if got := inboundAnswerDelay(&config.Config{AnswerAfter: 750 * time.Millisecond}); got != 750*time.Millisecond {
		t.Fatalf("overridden answer delay=%s", got)
	}
	if got := inboundAnswerDelay(&config.Config{RejectAfter: 500 * time.Millisecond}); got != 500*time.Millisecond {
		t.Fatalf("reject delay=%s", got)
	}
}

func TestInboundProvisionalResponsePreservesDefaultRinging(t *testing.T) {
	response := inboundProvisionalResponse(&config.Config{}, "v=0")
	if response.statusCode != 180 || response.reason != "Ringing" || response.body != "" || response.contentType != "" {
		t.Fatalf("default provisional response=%+v", response)
	}

	response = inboundProvisionalResponse(&config.Config{EarlyMedia: true}, "v=0")
	if response.statusCode != 183 || response.reason != "Session Progress" || response.body != "v=0" || response.contentType != "application/sdp" {
		t.Fatalf("early-media provisional response=%+v", response)
	}
}

func TestWaitBeforeInboundAnswerVerifiesEarlyVideoPackets(t *testing.T) {
	receiver := listenAppTestUDP(t)
	sender := listenAppTestUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go func() {
		for sequence := uint16(1); sequence <= 3; sequence++ {
			_, _ = sender.WriteToUDP(buildAppTestRTP(sequence), receiver.LocalAddr().(*net.UDPAddr))
		}
	}()
	waitForCancel := func(ctx context.Context) (bool, error) {
		<-ctx.Done()
		return false, nil
	}

	wasCancelled, reception, err := waitBeforeInboundAnswer(ctx, waitForCancel, receiver, 3)
	if err != nil {
		t.Fatalf("waitBeforeInboundAnswer error: %v", err)
	}
	if wasCancelled {
		t.Fatal("answer wait was treated as cancelled")
	}
	if reception.PacketCount != 3 {
		t.Fatalf("early video packet count=%d", reception.PacketCount)
	}
}

func TestWaitBeforeInboundAnswerFailsWithoutRequiredVideo(t *testing.T) {
	receiver := listenAppTestUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	waitForCancel := func(ctx context.Context) (bool, error) {
		<-ctx.Done()
		return false, nil
	}

	_, reception, err := waitBeforeInboundAnswer(ctx, waitForCancel, receiver, 1)
	if err == nil || !strings.Contains(err.Error(), "received 0 of 1") {
		t.Fatalf("reception=%+v error=%v", reception, err)
	}
}

func TestWaitBeforeInboundAnswerPreservesVerifiedVideoWhenCancelled(t *testing.T) {
	receiver := listenAppTestUDP(t)
	sender := listenAppTestUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		for sequence := uint16(1); sequence <= 3; sequence++ {
			_, _ = sender.WriteToUDP(buildAppTestRTP(sequence), receiver.LocalAddr().(*net.UDPAddr))
		}
	}()
	waitForCancel := func(context.Context) (bool, error) {
		time.Sleep(10 * time.Millisecond)
		return true, nil
	}

	wasCancelled, reception, err := waitBeforeInboundAnswer(ctx, waitForCancel, receiver, 3)
	if err != nil {
		t.Fatalf("waitBeforeInboundAnswer error: %v", err)
	}
	if !wasCancelled {
		t.Fatal("cancel was not reported")
	}
	if reception.PacketCount != 3 {
		t.Fatalf("early video packet count=%d", reception.PacketCount)
	}
}

func listenAppTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func buildAppTestRTP(sequence uint16) []byte {
	packet := make([]byte, 13)
	packet[0] = 2 << 6
	packet[1] = 96
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], uint32(sequence)*3000)
	binary.BigEndian.PutUint32(packet[8:12], 0x259989ef)
	packet[12] = 0x65
	return packet
}

type fakeInboundRequestHandler struct {
	calls  atomic.Int32
	method string
}

func (f *fakeInboundRequestHandler) HandleIncomingRequest(ctx context.Context) (string, error) {
	f.calls.Add(1)
	if f.method != "" {
		return f.method, nil
	}
	<-ctx.Done()
	return "", ctx.Err()
}

func TestDestinationFromAnswer_EarlyAndFinalSwitch(t *testing.T) {
	early, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.10",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 4000}, {Type: "video", Port: 5000}},
	}, netutil.IPFamilyV4, replay.MediaStateEarly, true)
	if err != nil {
		t.Fatalf("early destination error: %v", err)
	}
	if got := early.AudioAddr.String(); got != "192.0.2.10:4000" {
		t.Fatalf("early audio addr=%s", got)
	}

	final, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.20",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 6000}, {Type: "video", Port: 7000}},
	}, netutil.IPFamilyV4, replay.MediaStateFinal, true)
	if err != nil {
		t.Fatalf("final destination error: %v", err)
	}
	if got := final.AudioAddr.String(); got != "192.0.2.20:6000" {
		t.Fatalf("final audio addr=%s", got)
	}
	if got := final.VideoAddr.String(); got != "192.0.2.20:7000" {
		t.Fatalf("final video addr=%s", got)
	}
}

func TestDestinationFromAnswer_DisablesMediaPortZeroOnFinal(t *testing.T) {
	dest, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.30",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 0}, {Type: "video", Port: 7002}},
	}, netutil.IPFamilyV4, replay.MediaStateFinal, true)
	if err != nil {
		t.Fatalf("destination error: %v", err)
	}
	if dest.AudioAddr != nil {
		t.Fatalf("audio should be disabled")
	}
	if got := dest.VideoAddr.String(); got != "192.0.2.30:7002" {
		t.Fatalf("video addr=%s", got)
	}
}

func TestDestinationFromAnswer_NoUsableEndpoints(t *testing.T) {
	_, err := destinationFromAnswer(sipclient.SDPAnswer{
		ConnectionIP: "192.0.2.30",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 0}, {Type: "video", Port: 0}},
	}, netutil.IPFamilyV4, replay.MediaStateFinal, true)
	if err == nil {
		t.Fatalf("expected error for no usable endpoints")
	}
}

func TestDestinationFromAnswer_FamilyValidation(t *testing.T) {
	tests := []struct {
		name      string
		family    netutil.IPFamily
		sdpIP     string
		expectErr string
	}{
		{name: "ipv4 accepts ip4", family: netutil.IPFamilyV4, sdpIP: "192.0.2.10"},
		{name: "ipv4 rejects ip6", family: netutil.IPFamilyV4, sdpIP: "2001:db8::1", expectErr: "local-ip family IPv4 is incompatible"},
		{name: "ipv6 accepts ip6", family: netutil.IPFamilyV6, sdpIP: "2001:db8::1"},
		{name: "ipv6 rejects ip4", family: netutil.IPFamilyV6, sdpIP: "192.0.2.10", expectErr: "local-ip family IPv6 is incompatible"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := destinationFromAnswer(sipclient.SDPAnswer{
				ConnectionIP: tt.sdpIP,
				Media:        []sipclient.SDPMedia{{Type: "audio", Port: 4000}},
			}, tt.family, replay.MediaStateFinal, true)
			if tt.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectErr) {
					t.Fatalf("expected error containing %q, got %v", tt.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dest.AudioAddr == nil {
				t.Fatalf("expected audio destination")
			}
		})
	}
}

func TestParseAndValidateSDPAddr_NormalizesBracketedIPv6(t *testing.T) {
	tests := []struct {
		name      string
		family    netutil.IPFamily
		network   string
		ip        string
		port      int
		expectErr bool
	}{
		{
			name:    "valid ipv6",
			family:  netutil.IPFamilyV6,
			network: "udp6",
			ip:      "2a01:4f9:c012:f13::1",
			port:    4000,
		},
		{
			name:    "bracketed ipv6",
			family:  netutil.IPFamilyV6,
			network: "udp6",
			ip:      "[2a01:4f9:c012:f13::1]",
			port:    4000,
		},
		{
			name:    "ipv4",
			family:  netutil.IPFamilyV4,
			network: "udp4",
			ip:      "192.168.1.10",
			port:    4000,
		},
		{
			name:      "invalid",
			family:    netutil.IPFamilyV6,
			network:   "udp6",
			ip:        "[invalid-ip]",
			port:      4000,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := parseAndValidateSDPAddr(tt.family, tt.network, tt.ip, tt.port)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr == nil {
				t.Fatalf("expected address")
			}
		})
	}
}

func TestStartInboundRequestLoop_StopsOnCancel(t *testing.T) {
	handler := &fakeInboundRequestHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	done := startInboundRequestLoop(ctx, handler)

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case method := <-done:
		if method != "" {
			t.Fatalf("method=%q, want empty", method)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request loop did not stop after cancel")
	}

	callsAtStop := handler.calls.Load()
	time.Sleep(50 * time.Millisecond)
	if got := handler.calls.Load(); got != callsAtStop {
		t.Fatalf("handler calls advanced after loop stop: before=%d after=%d", callsAtStop, got)
	}
}

func TestStartInboundRequestLoopReportsRemoteBye(t *testing.T) {
	handler := &fakeInboundRequestHandler{method: "BYE"}
	result := startInboundRequestLoop(context.Background(), handler)

	select {
	case method := <-result:
		if method != "BYE" {
			t.Fatalf("method=%q, want BYE", method)
		}
	case <-time.After(time.Second):
		t.Fatal("request loop did not report BYE")
	}
}

func TestWaitForRemoteByeDistinguishesByeFromTimeout(t *testing.T) {
	remoteBye := make(chan string, 1)
	remoteBye <- "BYE"
	if !waitForRemoteBye(remoteBye, time.Second) {
		t.Fatal("BYE was not detected")
	}

	noRequest := make(chan string)
	if waitForRemoteBye(noRequest, time.Millisecond) {
		t.Fatal("timeout was treated as BYE")
	}
}

func TestStopInboundRequestLoopDetectsByeAtGraceBoundary(t *testing.T) {
	requestResult := make(chan string, 1)
	requestResult <- "BYE"
	cancelled := false
	if !stopInboundRequestLoop(func() { cancelled = true }, requestResult) {
		t.Fatal("BYE at grace boundary was not detected")
	}
	if !cancelled {
		t.Fatal("request loop context was not cancelled")
	}
}

func TestPayloadTypeMapFromNegotiation(t *testing.T) {
	got := payloadTypeMapFromNegotiation(sdp.NegotiatedMedia{PayloadTypeMappings: []sdp.PayloadTypeNegotiation{
		{MediaType: "audio", LocalPT: 101, NegotiatedPT: 101},
		{MediaType: "audio", LocalPT: 110, NegotiatedPT: 111},
		{MediaType: "video", LocalPT: 96, NegotiatedPT: 99},
	}})

	want := replay.PayloadTypeMap{
		Audio: map[uint8]uint8{110: 111},
		Video: map[uint8]uint8{96: 99},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payloadTypeMapFromNegotiation=%#v want %#v", got, want)
	}
}
