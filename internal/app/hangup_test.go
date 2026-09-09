package app

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
	"sip-tester/internal/pcapread"
	"sip-tester/internal/replay"
	"sip-tester/internal/sipclient"
)

func TestLocalHangupSendsBYEAfterReplay(t *testing.T) {
	for _, callMode := range []string{"outbound", "inbound"} {
		t.Run(callMode, func(t *testing.T) {
			t.Parallel()
			call := startHangupTestCall(t, callMode, "local", 0)
			request, response := call.readSIP(t, 2*time.Second)
			if request == nil || request.Method != "BYE" || response != nil {
				t.Fatalf("expected local BYE, got request=%+v response=%+v", request, response)
			}
			call.respond(t, request, "", "")
			call.requireFinished(t, 2*time.Second, "")
		})
	}
}

func TestRemoteBYEEndsReplayWithoutLocalBYE(t *testing.T) {
	for _, callMode := range []string{"outbound", "inbound"} {
		for _, hangupMode := range []string{"local", "remote"} {
			t.Run(callMode+"/"+hangupMode, func(t *testing.T) {
				t.Parallel()
				call := startHangupTestCall(t, callMode, hangupMode, 5*time.Second)
				call.sendDialogRequest(t, "BYE")
				call.requireResponse(t, "BYE")
				call.requireFinished(t, 2*time.Second, "")
				call.requireNoLocalBYE(t)
			})
		}
	}
}

func TestRemoteHangupWaitsAfterReplayAndStillAnswersINFO(t *testing.T) {
	for _, callMode := range []string{"outbound", "inbound"} {
		t.Run(callMode, func(t *testing.T) {
			t.Parallel()
			call := startHangupTestCall(t, callMode, "remote", 0)
			<-call.setup.replayController.done
			call.sendDialogRequest(t, "INFO")
			call.requireResponse(t, "INFO")
			select {
			case err := <-call.finished:
				t.Fatalf("remote mode finished before BYE: %v", err)
			default:
			}
			call.sendDialogRequest(t, "BYE")
			call.requireResponse(t, "BYE")
			call.requireFinished(t, 2*time.Second, "")
			call.requireNoLocalBYE(t)
		})
	}
}

func TestRemoteHangupTimeoutFailsWithoutSendingBYE(t *testing.T) {
	t.Parallel()
	call := startHangupTestCall(t, "outbound", "remote", 0)
	call.requireFinished(t, 18*time.Second, "wait for remote BYE")
	call.requireNoLocalBYE(t)
}

func TestReplayFailureFailsCallWithoutSendingBYE(t *testing.T) {
	for _, hangupMode := range []string{"local", "remote"} {
		t.Run(hangupMode, func(t *testing.T) {
			t.Parallel()
			call := startHangupTestCall(t, "outbound", hangupMode, 750*time.Millisecond)
			if err := call.setup.transportStore.Get().Sockets.AudioConn.Close(); err != nil {
				t.Fatal(err)
			}
			call.requireFinished(t, 2*time.Second, "RTP replay")
			call.requireNoLocalBYE(t)
		})
	}
}

func TestFinalVideoRequirementDelaysLocalBYEUntilEnoughPackets(t *testing.T) {
	call := startHangupTestCall(t, "inbound", "local", 0, hangupCallOptions{finalVideoPackets: 2})
	call.sendVideoPackets(t, 1)
	call.sendDialogRequest(t, "INFO")
	call.requireResponse(t, "INFO")
	call.sendVideoPackets(t, 1)
	bye, _ := call.readSIP(t, 2*time.Second)
	if bye == nil || bye.Method != "BYE" {
		t.Fatalf("expected BYE after receiving required video, got %+v", bye)
	}
	call.respond(t, bye, "", "")
	call.requireFinished(t, time.Second, "")
}

func TestRemoteBYEDoesNotHideMissingFinalVideo(t *testing.T) {
	for _, hangupMode := range []string{"local", "remote"} {
		t.Run(hangupMode, func(t *testing.T) {
			t.Parallel()
			call := startHangupTestCall(t, "inbound", hangupMode, 5*time.Second, hangupCallOptions{finalVideoPackets: 2})
			call.sendDialogRequest(t, "BYE")
			call.requireResponse(t, "BYE")
			call.requireFinished(t, 2*time.Second, "required RTP packets")
			call.requireNoLocalBYE(t)
		})
	}
}

func TestFinalVideoTimeoutFailsWithoutLocalBYE(t *testing.T) {
	t.Parallel()
	call := startHangupTestCall(t, "inbound", "local", 0, hangupCallOptions{finalVideoPackets: 2})
	call.requireFinished(t, 18*time.Second, "received 0 of 2 required RTP packets")
	call.requireNoLocalBYE(t)
}

func TestRemoteHangupDeadlineIncludesFinalVideoVerification(t *testing.T) {
	t.Parallel()
	call := startHangupTestCall(t, "inbound", "remote", 0, hangupCallOptions{finalVideoPackets: 1})
	<-call.setup.replayController.done
	hangupDeadline := time.Now().Add(16 * time.Second)
	time.Sleep(4 * time.Second)
	call.sendVideoPackets(t, 1)
	call.requireFinished(t, time.Until(hangupDeadline), "wait for remote BYE")
	call.requireNoLocalBYE(t)
}

func TestFinalVideoReadFailureFailsCallWithoutLocalBYE(t *testing.T) {
	t.Parallel()
	call := startHangupTestCall(t, "inbound", "local", 5*time.Second, hangupCallOptions{finalVideoPackets: 2})
	if err := call.setup.transportStore.Get().Sockets.VideoConn.Close(); err != nil {
		t.Fatal(err)
	}
	call.requireFinished(t, 2*time.Second, "verify final video RTP")
	call.requireNoLocalBYE(t)
}

func TestRemoteBYEDuringReinviteStopsCall(t *testing.T) {
	for _, hangupMode := range []string{"local", "remote"} {
		t.Run(hangupMode, func(t *testing.T) {
			t.Parallel()
			call := startHangupTestCall(t, "inbound", hangupMode, 5*time.Second, hangupCallOptions{reinviteAfter: 10 * time.Millisecond})
			reinvite, _ := call.readSIP(t, 2*time.Second)
			if reinvite == nil || reinvite.Method != "INVITE" {
				t.Fatalf("expected re-INVITE, got %+v", reinvite)
			}
			call.sendDialogRequest(t, "BYE")
			call.requireResponse(t, "BYE")
			call.requireFinished(t, 2*time.Second, "")
			call.requireNoLocalBYE(t)
		})
	}
}

func TestLocalReplayCompletionSendsBYEWhileReinviteIsPending(t *testing.T) {
	call := startHangupTestCall(t, "inbound", "local", 150*time.Millisecond, hangupCallOptions{reinviteAfter: 10 * time.Millisecond})
	reinvite, _ := call.readSIP(t, 2*time.Second)
	if reinvite == nil || reinvite.Method != "INVITE" {
		t.Fatalf("expected re-INVITE, got %+v", reinvite)
	}
	bye, _ := call.readSIP(t, 2*time.Second)
	if bye == nil || bye.Method != "BYE" {
		t.Fatalf("expected BYE after replay, got %+v", bye)
	}
	call.respond(t, bye, "", "")
	call.requireFinished(t, time.Second, "")
}

func TestRemoteWaitDoesNotStartReinviteAfterReplay(t *testing.T) {
	call := startHangupTestCall(t, "inbound", "remote", 0, hangupCallOptions{reinviteAfter: 10 * time.Millisecond})
	<-call.setup.replayController.done
	if err := call.server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	length, _, err := call.server.ReadFromUDP(packet)
	if err == nil {
		t.Fatalf("unexpected re-INVITE after RTP completion: %s", packet[:length])
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatal(err)
	}
	call.sendDialogRequest(t, "BYE")
	call.requireResponse(t, "BYE")
	call.requireFinished(t, time.Second, "")
}

type hangupTestCall struct {
	server   *net.UDPConn
	setup    *runSetup
	finished <-chan error
	callID   string
	from     string
	to       string
}

type hangupCallOptions struct {
	reinviteAfter     time.Duration
	finalVideoPackets int
}

func startHangupTestCall(t *testing.T, callMode, hangupMode string, replayDuration time.Duration, options ...hangupCallOptions) *hangupTestCall {
	t.Helper()
	server := listenHangupUDP(t)
	mediaReceiver := listenHangupUDP(t)
	mediaSender := listenHangupUDP(t)
	client, err := sipclient.NewClient(net.ParseIP("127.0.0.1"), netutil.IPFamilyV4, netutil.ResolvedTarget{
		Hostname: "127.0.0.1", Port: uint16(server.LocalAddr().(*net.UDPAddr).Port),
		RemoteIP: net.ParseIP("127.0.0.1"), RemoteAddr: server.LocalAddr().String(), Family: netutil.IPFamilyV4,
	}, "", "", "hangup-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	transport := &replay.MediaTransportStore{}
	transport.Set(replay.MediaTransport{Sockets: replay.MediaSockets{AudioConn: mediaSender}})
	setup := &runSetup{
		logger: log.New(io.Discard, "", 0),
		cfg: &config.Config{
			Mode: callMode, HangupMode: hangupMode,
			Caller: "sip:1001@127.0.0.1", Callee: "sip:1002@127.0.0.1",
			LocalIPParsed: net.ParseIP("127.0.0.1"), IPFamily: netutil.IPFamilyV4,
		},
		client: client, transportStore: transport,
		network: "udp4", mediaSockets: &mediaSocketPool{}, bindMediaSockets: replay.BindMediaSockets,
		audioPort:  mediaSender.LocalAddr().(*net.UDPAddr).Port,
		videoPort:  mediaSender.LocalAddr().(*net.UDPAddr).Port,
		localMedia: []pcapread.SDPMedia{{Media: "audio", PayloadTypes: []int{0}}},
	}
	t.Cleanup(setup.mediaSockets.Close)
	if len(options) > 0 {
		setup.cfg.ReinviteAfter = options[0].reinviteAfter
		setup.cfg.RequireFinalVideoPackets = options[0].finalVideoPackets
	}
	if setup.cfg.RequireFinalVideoPackets > 0 {
		videoReceiver := listenHangupUDP(t)
		setup.videoPort = videoReceiver.LocalAddr().(*net.UDPAddr).Port
		setup.localMedia = append(setup.localMedia, pcapread.SDPMedia{Media: "video", PayloadTypes: []int{96}})
		transport.Set(replay.MediaTransport{Sockets: replay.MediaSockets{AudioConn: mediaSender, VideoConn: videoReceiver}})
	}
	schedule := []replay.ScheduledPacket{{MediaType: replay.MediaTypeAudio, Packet: pcapread.RTPPacket{SSRC: 1234}}}
	if replayDuration > 0 {
		schedule = append(schedule, replay.ScheduledPacket{At: replayDuration, MediaType: replay.MediaTypeAudio, Packet: pcapread.RTPPacket{SSRC: 1234, Sequence: 1}})
	}
	setup.replayController = newReplayController(setup.logger, schedule, transport)
	finished := make(chan error, 1)
	call := &hangupTestCall{server: server, setup: setup, finished: finished}
	go func() {
		if callMode == "outbound" {
			finished <- runOutbound(setup)
		} else {
			finished <- runInbound(setup)
		}
	}()
	remoteSDP := fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n", mediaReceiver.LocalAddr().(*net.UDPAddr).Port)
	if setup.cfg.RequireFinalVideoPackets > 0 {
		remoteSDP += fmt.Sprintf("m=video %d RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n", mediaReceiver.LocalAddr().(*net.UDPAddr).Port)
	}
	initialRequest, _ := call.readSIP(t, 2*time.Second)
	if initialRequest == nil {
		t.Fatal("expected initial SIP request")
	}
	if callMode == "outbound" {
		if initialRequest.Method != "INVITE" {
			t.Fatalf("expected INVITE, got %s", initialRequest.Method)
		}
		call.callID = initialRequest.GetHeader("Call-ID")
		call.from = initialRequest.GetHeader("To") + ";tag=remote"
		call.to = initialRequest.GetHeader("From")
		call.respond(t, initialRequest, call.from, remoteSDP)
		ack, _ := call.readSIP(t, 2*time.Second)
		if ack == nil || ack.Method != "ACK" {
			t.Fatalf("expected ACK, got %+v", ack)
		}
	} else {
		if initialRequest.Method != "REGISTER" {
			t.Fatalf("expected REGISTER, got %s", initialRequest.Method)
		}
		call.respond(t, initialRequest, "", "")
		call.callID = "inbound-hangup-call"
		call.from = "<sip:1002@127.0.0.1>;tag=remote"
		call.to = "<sip:1001@127.0.0.1>"
		invite := call.dialogRequest("INVITE")
		invite.Headers["Contact"] = "<sip:1002@" + server.LocalAddr().String() + ">"
		invite.Headers["Content-Type"] = "application/sdp"
		invite.Body = remoteSDP
		call.send(t, sip.BuildRequest(invite))
		_, ringing := call.readSIP(t, 2*time.Second)
		if ringing == nil || ringing.StatusCode != 180 {
			t.Fatalf("expected ringing response, got %+v", ringing)
		}
		_, answer := call.readSIP(t, 5*time.Second)
		if answer == nil || answer.StatusCode != 200 {
			t.Fatalf("expected answer, got %+v", answer)
		}
		call.to = answer.GetHeader("To")
		call.sendDialogRequest(t, "ACK")
	}
	if err := mediaReceiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mediaReceiver.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatalf("wait for established RTP stream: %v", err)
	}
	return call
}

func listenHangupUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func (call *hangupTestCall) readSIP(t *testing.T, timeout time.Duration) (*sip.Request, *sip.Response) {
	t.Helper()
	if err := call.server.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	length, _, err := call.server.ReadFromUDP(packet)
	if err != nil {
		select {
		case callError := <-call.finished:
			t.Fatalf("receive SIP: %v; call returned: %v", err, callError)
		default:
		}
		t.Fatalf("receive SIP: %v", err)
	}
	request, response, err := sip.ParseMessage(packet[:length])
	if err != nil {
		t.Fatal(err)
	}
	return request, response
}

func (call *hangupTestCall) respond(t *testing.T, request *sip.Request, to, body string) {
	t.Helper()
	if to == "" {
		to = request.GetHeader("To")
	}
	call.send(t, sip.BuildResponse(&sip.Response{StatusCode: 200, Reason: "OK", Headers: map[string]string{
		"Via": request.GetHeader("Via"), "From": request.GetHeader("From"), "To": to,
		"Call-ID": request.GetHeader("Call-ID"), "CSeq": request.GetHeader("CSeq"),
		"Contact": "<sip:1002@" + call.server.LocalAddr().String() + ">", "Content-Type": "application/sdp",
	}, Body: body}))
}

func (call *hangupTestCall) dialogRequest(method string) *sip.Request {
	return &sip.Request{Method: method, URI: "sip:1001@127.0.0.1", Headers: map[string]string{
		"Via":  "SIP/2.0/UDP " + call.server.LocalAddr().String() + ";branch=z9hG4bK-" + method,
		"From": call.from, "To": call.to, "Call-ID": call.callID, "CSeq": "1 " + method,
	}}
}

func (call *hangupTestCall) sendDialogRequest(t *testing.T, method string) {
	t.Helper()
	call.send(t, sip.BuildRequest(call.dialogRequest(method)))
}

func (call *hangupTestCall) sendVideoPackets(t *testing.T, count int) {
	t.Helper()
	videoAddress := call.setup.transportStore.Get().Sockets.VideoConn.LocalAddr().(*net.UDPAddr)
	for sequence := 1; sequence <= count; sequence++ {
		if _, err := call.server.WriteToUDP(buildAppTestRTP(uint16(sequence)), videoAddress); err != nil {
			t.Fatal(err)
		}
	}
}

func (call *hangupTestCall) send(t *testing.T, packet []byte) {
	t.Helper()
	if _, err := call.server.WriteToUDP(packet, call.setup.client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
}

func (call *hangupTestCall) requireResponse(t *testing.T, method string) {
	t.Helper()
	request, response := call.readSIP(t, 2*time.Second)
	if request != nil || response == nil || response.StatusCode != 200 || response.GetHeader("CSeq") != "1 "+method || response.GetHeader("Call-ID") != call.callID {
		t.Fatalf("expected 200 OK for %s, got request=%+v response=%+v", method, request, response)
	}
}

func (call *hangupTestCall) requireFinished(t *testing.T, timeout time.Duration, expectedError string) {
	t.Helper()
	select {
	case err := <-call.finished:
		if expectedError == "" && err != nil {
			t.Fatalf("call failed: %v", err)
		}
		if expectedError != "" && (err == nil || !strings.Contains(err.Error(), expectedError)) {
			t.Fatalf("expected error containing %q, got %v", expectedError, err)
		}
	case <-time.After(timeout):
		t.Fatal("call did not finish")
	}
}

func (call *hangupTestCall) requireNoLocalBYE(t *testing.T) {
	t.Helper()
	if err := call.server.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	length, _, err := call.server.ReadFromUDP(packet)
	if err == nil {
		t.Fatalf("unexpected SIP after call completion: %s", packet[:length])
	}
	if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("receive after completion: %v", err)
	}
}
