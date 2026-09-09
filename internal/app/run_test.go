package app

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
	"sip-tester/internal/pcapread"
	"sip-tester/internal/replay"
	"sip-tester/internal/sdp"
	"sip-tester/internal/sipclient"
)

type fakeInboundRequestHandler struct {
	calls atomic.Int32
}

type fakeReinviteDialog struct {
	offer  string
	answer sipclient.SDPAnswer
	err    error
}

func (dialog *fakeReinviteDialog) Reinvite(_ context.Context, offer string) (sipclient.SDPAnswer, error) {
	dialog.offer = offer
	return dialog.answer, dialog.err
}

func (f *fakeInboundRequestHandler) HandleIncomingRequest(ctx context.Context) (string, error) {
	f.calls.Add(1)
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
	done := startDialogRequestLoop(ctx, handler, nil, 0, nil)

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("request loop error: %v", result.err)
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

func TestStartInboundRequestLoop_RunsScheduledReinviteOnce(t *testing.T) {
	handler := &fakeInboundRequestHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reinviteCalls := make(chan struct{}, 2)
	done := startDialogRequestLoop(ctx, handler, nil, 10*time.Millisecond, func(context.Context) error {
		reinviteCalls <- struct{}{}
		return nil
	})

	select {
	case <-reinviteCalls:
	case <-time.After(time.Second):
		t.Fatal("scheduled re-INVITE was not called")
	}
	time.Sleep(30 * time.Millisecond)
	select {
	case <-reinviteCalls:
		t.Fatal("scheduled re-INVITE was called more than once")
	default:
	}

	cancel()
	if result := <-done; result.err != nil {
		t.Fatalf("request loop error: %v", result.err)
	}
}

func TestStartInboundRequestLoop_ReturnsReinviteError(t *testing.T) {
	handler := &fakeInboundRequestHandler{}
	wantErr := errors.New("re-INVITE rejected")
	done := startDialogRequestLoop(context.Background(), handler, nil, time.Millisecond, func(context.Context) error {
		return wantErr
	})

	if result := <-done; !errors.Is(result.err, wantErr) {
		t.Fatalf("request loop error=%v, want %v", result.err, wantErr)
	}
}

func TestDialogRequestLoopPreservesReinviteFailureDuringCancellation(t *testing.T) {
	handler := &fakeInboundRequestHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantErr := errors.New("re-INVITE rejected with 488")
	done := startDialogRequestLoop(ctx, handler, nil, time.Millisecond, func(context.Context) error {
		cancel()
		return wantErr
	})
	if result := <-done; !errors.Is(result.err, wantErr) {
		t.Fatalf("request loop error=%v, want %v", result.err, wantErr)
	}
}

func TestRunSetupApplyReinvitePublishesBundledTransportAfterAnswer(t *testing.T) {
	oldConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen old RTP socket: %v", err)
	}
	defer oldConn.Close()
	transport := &replay.MediaTransportStore{}
	transport.Set(replay.MediaTransport{Sockets: replay.MediaSockets{AudioConn: oldConn, VideoConn: oldConn}})
	pool := &mediaSocketPool{}
	setup := &runSetup{
		logger:           log.New(io.Discard, "", 0),
		cfg:              &config.Config{LocalIPParsed: net.ParseIP("127.0.0.1"), IPFamily: netutil.IPFamilyV4, Bundle: true},
		network:          "udp4",
		localMedia:       []pcapread.SDPMedia{{Media: "audio", PayloadTypes: []int{0}}, {Media: "video", PayloadTypes: []int{96}}},
		transportStore:   transport,
		mediaSockets:     pool,
		bindMediaSockets: replay.BindMediaSockets,
	}
	dialog := &fakeReinviteDialog{answer: sipclient.SDPAnswer{
		ConnectionIP: "127.0.0.1",
		Media:        []sipclient.SDPMedia{{Type: "audio", Port: 22000}, {Type: "video", Port: 22000}},
	}}

	if err := setup.applyReinvite(context.Background(), dialog); err != nil {
		t.Fatalf("apply re-INVITE: %v", err)
	}
	defer pool.Close()

	if !strings.Contains(dialog.offer, "a=group:BUNDLE audio video") {
		t.Fatalf("re-INVITE offer does not advertise BUNDLE:\n%s", dialog.offer)
	}
	current := transport.Get()
	if current.Sockets.AudioConn == oldConn || current.Sockets.VideoConn == oldConn {
		t.Fatal("old RTP socket remained active after re-INVITE")
	}
	if current.Sockets.AudioConn != current.Sockets.VideoConn {
		t.Fatal("bundled media must use one local RTP socket")
	}
	if got := current.Destination.AudioAddr.String(); got != "127.0.0.1:22000" {
		t.Fatalf("audio destination=%s", got)
	}
	if got := current.Destination.VideoAddr.String(); got != "127.0.0.1:22000" {
		t.Fatalf("video destination=%s", got)
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
