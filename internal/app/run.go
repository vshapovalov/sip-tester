package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sip-tester/internal/cli"
	"sip-tester/internal/config"
	"sip-tester/internal/netutil"
	"sip-tester/internal/pcapread"
	"sip-tester/internal/replay"
	"sip-tester/internal/sdp"
	"sip-tester/internal/sipclient"
)

const defaultStepTimeout = 15 * time.Second

// Run executes the sip-tester orchestration flow.
func Run(args []string) error {
	logger := log.New(os.Stdout, "sip-tester: ", log.LstdFlags)

	logger.Println("parse CLI")
	cfg, err := cli.ParseArgs(args)
	if err != nil {
		return fmt.Errorf("parse CLI: %w", err)
	}

	logger.Printf("normalize URIs: caller=%s callee=%s", cfg.Caller, cfg.Callee)
	logger.Printf("local-ip=%s family=%s", cfg.LocalIPParsed.String(), cfg.IPFamily)
	logger.Printf("IP mode selected: %s", cfg.IPFamily)
	network, err := netutil.UDPNetworkForFamily(cfg.IPFamily)
	if err != nil {
		return err
	}
	logger.Printf("selected media network=%s local_ip=%s family=%s", network, cfg.LocalIPParsed.String(), cfg.IPFamily)

	logger.Printf("resolve SIP target: host=%s port=%d family=%s", cfg.Host, cfg.Port, cfg.IPFamily)
	resolvedTarget, err := netutil.ResolveSIPTarget(cfg.Host, cfg.Port, cfg.IPFamily)
	if err != nil {
		return fmt.Errorf("resolve SIP target: %w", err)
	}
	logger.Printf("resolved SIP target host=%s selected_ip=%s remote_addr=%s", resolvedTarget.Hostname, resolvedTarget.RemoteIP.String(), resolvedTarget.RemoteAddr)

	logger.Printf("load PCAP: %s", cfg.PCAP)
	packets, linkType, err := pcapread.LoadPCAPWithLinkType(cfg.PCAP)
	if err != nil {
		return fmt.Errorf("load PCAP: %w", err)
	}
	if cfg.Debug {
		for _, line := range pcapread.BuildPacketDiagnostics(linkType, packets, 8) {
			logger.Println(line)
		}
	}

	logger.Println("extract streams")
	streams := pcapread.ExtractRTPBySSRC(packets)
	if len(streams) == 0 {
		udpCount := pcapread.DecodableUDPCount(packets)
		if udpCount == 0 {
			return fmt.Errorf("extract streams: no decodable UDP packets found")
		}
		return fmt.Errorf("extract streams: no RTP packets found")
	}
	audioStream, videoStream, err := selectStreams(cfg.SSRCAudio, cfg.SSRCVideo, streams)
	if err != nil {
		return fmt.Errorf("extract streams: %w", err)
	}

	schedule := replay.BuildSchedule(audioStream, videoStream)
	if len(schedule) == 0 {
		return fmt.Errorf("no RTP packets scheduled")
	}

	logger.Println("build SDP")
	rawInviteSDP, err := pcapread.FindFirstInviteWithSDP(packets)
	if err != nil {
		return fmt.Errorf("find INVITE: %w", err)
	}
	media, err := pcapread.ParseSDPMedia(rawInviteSDP)
	if err != nil {
		return fmt.Errorf("parse INVITE SDP: %w", err)
	}

	audioConn, videoConn, audioPort, videoPort, err := replay.BindMediaSockets(network, cfg.LocalIPParsed)
	if err != nil {
		return fmt.Errorf("bind media sockets: %w", err)
	}
	defer audioConn.Close()
	defer videoConn.Close()
	logger.Printf("bound RTP audio socket: %s:%d", cfg.LocalIPParsed.String(), audioPort)
	logger.Printf("bound RTP video socket: %s:%d", cfg.LocalIPParsed.String(), videoPort)

	offer, err := sdp.BuildOffer(cfg.LocalIPParsed, audioPort, videoPort, media)
	if err != nil {
		return fmt.Errorf("build SDP offer: %w", err)
	}

	client, err := sipclient.NewClient(cfg.LocalIPParsed, cfg.IPFamily, resolvedTarget, cfg.Username, cfg.Password)
	if err != nil {
		return fmt.Errorf("create SIP client: %w", err)
	}
	defer client.Close()

	setup := &runSetup{
		logger:           logger,
		cfg:              cfg,
		schedule:         schedule,
		audioConn:        audioConn,
		videoConn:        videoConn,
		offer:            offer,
		client:           client,
		rtpStore:         &replay.MediaDestinationStore{},
		replayController: nil,
	}
	setup.replayController = newReplayController(logger, schedule, setup.rtpStore, audioConn, videoConn)

	if cfg.Mode == "inbound" {
		logger.Println("mode=inbound")
		return runInbound(setup)
	}
	return runOutbound(setup)
}

type runSetup struct {
	logger           *log.Logger
	cfg              *config.Config
	schedule         []replay.ScheduledPacket
	audioConn        net.PacketConn
	videoConn        net.PacketConn
	offer            string
	client           *sipclient.Client
	rtpStore         *replay.MediaDestinationStore
	replayController *replayRunner
}

func runOutbound(s *runSetup) error {
	cfg := s.cfg
	ctx, cancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer cancel()

	s.logger.Println("send INVITE")
	inviteRes, err := s.client.SendInviteWithEarlyMedia(ctx, cfg.Caller, cfg.Callee, s.offer, func(answer sipclient.SDPAnswer) error {
		s.logger.Println("early SDP detected (183 Session Progress)")
		earlyDest, err := destinationFromSDP(answer, cfg.IPFamily, replay.MediaStateEarly, false)
		if err != nil {
			return fmt.Errorf("183 SDP handling failed: %w", err)
		}
		s.rtpStore.Set(earlyDest)
		s.logger.Printf("early media destination audio=%s video=%s", udpAddrString(earlyDest.AudioAddr), udpAddrString(earlyDest.VideoAddr))
		if s.replayController.Start() {
			s.logger.Println("early media started")
		} else {
			s.logger.Println("early destination updated")
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.logger.Println("200 OK received")

	s.logger.Println("send ACK")
	if err := s.client.SendACK(cfg.Caller, inviteRes); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	if !s.replayController.Started() {
		s.logger.Println("start RTP replay")
		s.replayController.Start()
	}

	finalDest, err := destinationFromSDP(inviteRes.SDPAnswer, cfg.IPFamily, replay.MediaStateFinal, true)
	if err != nil {
		return fmt.Errorf("200 OK SDP handling failed: %w", err)
	}
	s.rtpStore.Set(finalDest)
	s.logger.Printf("final destination applied audio=%s video=%s", udpAddrString(finalDest.AudioAddr), udpAddrString(finalDest.VideoAddr))

	dialog := s.client.NewDialog(cfg.Caller, cfg.Callee, inviteRes)

	s.logger.Println("handle INFO")
	infoCtx, infoCancel := context.WithCancel(context.Background())
	go handleInfoLoop(infoCtx, s.logger, dialog)

	s.replayController.Wait()
	infoCancel()

	if err := s.replayController.Err(); err != nil {
		return fmt.Errorf("RTP replay: %w", err)
	}

	byeCtx, byeCancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer byeCancel()
	s.logger.Println("send BYE")
	if err := dialog.Bye(byeCtx); err != nil {
		return fmt.Errorf("send BYE: %w", err)
	}

	s.logger.Println("exit")
	return nil
}

func runInbound(s *runSetup) error {
	cfg := s.cfg

	contact, err := sipclient.BuildRegisterContact(cfg.Caller, s.client.LocalAddr())
	if err != nil {
		return fmt.Errorf("build REGISTER Contact: %w", err)
	}

	regCtx, regCancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer regCancel()
	s.logger.Println("send REGISTER")
	if err := s.client.Register(regCtx, cfg.Caller, contact, 300); err != nil {
		return err
	}
	s.logger.Println("REGISTER succeeded")

	inviteCtx, inviteCancel := context.WithTimeout(context.Background(), 2*defaultStepTimeout)
	defer inviteCancel()
	s.logger.Println("waiting for incoming INVITE")
	inviteReq, inviteAddr, err := s.client.WaitForInvite(inviteCtx)
	if err != nil {
		return fmt.Errorf("wait INVITE: %w", err)
	}
	s.logger.Println("incoming INVITE received")

	offer, err := sipclient.ParseSDP(inviteReq.Body)
	if err != nil {
		return fmt.Errorf("parse inbound INVITE SDP: %w", err)
	}
	dialog, err := s.client.NewInboundDialog(inviteReq, cfg.Caller)
	if err != nil {
		return fmt.Errorf("create inbound dialog: %w", err)
	}

	s.logger.Println("send 180 Ringing")
	if err := dialog.SendInviteResponse(inviteReq, inviteAddr, 180, "Ringing", "", ""); err != nil {
		return fmt.Errorf("send 180: %w", err)
	}
	time.Sleep(3 * time.Second)
	s.logger.Println("send 200 OK")
	if err := dialog.SendInviteResponse(inviteReq, inviteAddr, 200, "OK", s.offer, "application/sdp"); err != nil {
		return fmt.Errorf("send 200 OK: %w", err)
	}

	ackCtx, ackCancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer ackCancel()
	if err := dialog.WaitForACK(ackCtx); err != nil {
		return fmt.Errorf("wait ACK: %w", err)
	}
	s.logger.Println("ACK received")

	finalDest, err := destinationFromSDP(offer, cfg.IPFamily, replay.MediaStateFinal, true)
	if err != nil {
		return fmt.Errorf("INVITE SDP handling failed: %w", err)
	}
	s.rtpStore.Set(finalDest)

	s.logger.Println("start RTP replay")
	s.replayController.Start()
	infoCtx, infoCancel := context.WithCancel(context.Background())
	go func() {
		defer infoCancel()
		for {
			select {
			case <-infoCtx.Done():
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			method, err := dialog.HandleIncomingRequest(ctx)
			cancel()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					continue
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				continue
			}
			if method == "BYE" {
				return
			}
		}
	}()

	s.replayController.Wait()
	infoCancel()
	if err := s.replayController.Err(); err != nil {
		return fmt.Errorf("RTP replay: %w", err)
	}
	s.logger.Println("replay finished")

	byeCtx, byeCancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer byeCancel()
	s.logger.Println("send BYE")
	if err := dialog.Bye(byeCtx); err != nil {
		return fmt.Errorf("send BYE: %w", err)
	}
	s.logger.Println("exit")
	return nil
}

type replayRunner struct {
	logger    *log.Logger
	schedule  []replay.ScheduledPacket
	store     *replay.MediaDestinationStore
	audioConn net.PacketConn
	videoConn net.PacketConn
	mu        sync.Mutex
	started   bool
	wg        sync.WaitGroup
	err       error
	errSet    bool
}

func newReplayController(logger *log.Logger, schedule []replay.ScheduledPacket, store *replay.MediaDestinationStore, audioConn, videoConn net.PacketConn) *replayRunner {
	return &replayRunner{logger: logger, schedule: schedule, store: store, audioConn: audioConn, videoConn: videoConn}
}

func (r *replayRunner) Start() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return false
	}
	r.started = true
	r.wg.Add(1)
	go r.run()
	return true
}

func (r *replayRunner) Started() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}

func (r *replayRunner) Wait() { r.wg.Wait() }

func (r *replayRunner) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *replayRunner) run() {
	defer r.wg.Done()
	r.logger.Println("replay started")
	sender := replay.NewUDPSender(r.audioConn, r.videoConn, r.store)
	if err := sender.Replay(context.Background(), r.schedule); err != nil {
		r.setErr(err)
		return
	}
	r.logger.Println("replay finished")
}

func (r *replayRunner) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.errSet {
		r.err = err
		r.errSet = true
	}
}

func selectStreams(audioSSRC, videoSSRC *uint32, streams map[uint32][]pcapread.RTPPacket) ([]pcapread.RTPPacket, []pcapread.RTPPacket, error) {
	var audio []pcapread.RTPPacket
	var video []pcapread.RTPPacket
	if audioSSRC != nil {
		pkts, ok := streams[*audioSSRC]
		if !ok {
			return nil, nil, fmt.Errorf("audio stream 0x%08x not found", *audioSSRC)
		}
		audio = pkts
	}
	if videoSSRC != nil {
		pkts, ok := streams[*videoSSRC]
		if !ok {
			return nil, nil, fmt.Errorf("video stream 0x%08x not found", *videoSSRC)
		}
		video = pkts
	}
	if len(audio) == 0 && len(video) == 0 {
		return nil, nil, fmt.Errorf("no RTP streams selected")
	}
	return audio, video, nil
}

func destinationFromSDP(answer sipclient.SDPAnswer, family netutil.IPFamily, state replay.MediaState, enforceUsable bool) (replay.MediaDestination, error) {
	dest := replay.MediaDestination{State: state}
	network, err := netutil.UDPNetworkForFamily(family)
	if err != nil {
		return replay.MediaDestination{}, err
	}
	for _, m := range answer.Media {
		ip := m.ConnectionIP
		if ip == "" {
			ip = answer.ConnectionIP
		}
		if ip == "" {
			continue
		}
		switch m.Type {
		case "audio":
			if m.Port == 0 {
				if state == replay.MediaStateFinal {
					log.Printf("sip-tester: media disabled type=audio")
				}
				continue
			}
			addr, err := parseAndValidateSDPAddr(family, network, ip, m.Port)
			if err != nil {
				return replay.MediaDestination{}, err
			}
			dest.AudioAddr = addr
		case "video":
			if m.Port == 0 {
				if state == replay.MediaStateFinal {
					log.Printf("sip-tester: media disabled type=video")
				}
				continue
			}
			addr, err := parseAndValidateSDPAddr(family, network, ip, m.Port)
			if err != nil {
				return replay.MediaDestination{}, err
			}
			dest.VideoAddr = addr
		}
	}
	if enforceUsable && dest.AudioAddr == nil && dest.VideoAddr == nil {
		return replay.MediaDestination{}, fmt.Errorf("no usable media endpoints in SDP")
	}
	return dest, nil
}

func destinationFromAnswer(answer sipclient.SDPAnswer, family netutil.IPFamily, state replay.MediaState, enforceUsable bool) (replay.MediaDestination, error) {
	return destinationFromSDP(answer, family, state, enforceUsable)
}

func parseAndValidateSDPAddr(family netutil.IPFamily, network, ip string, port int) (*net.UDPAddr, error) {
	originalIP := ip
	ip = normalizeIP(ip)
	if originalIP != ip {
		log.Printf("sip-tester: normalized SDP IP %s -> %s", originalIP, ip)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("SDP remote media address is not a literal IP: %s", ip)
	}
	if !netutil.IsIPInFamily(parsed, family) {
		if family == netutil.IPFamilyV4 {
			log.Printf("sip-tester: rejecting SDP destination %s:%d due to family mismatch local-ip-family=%s", ip, port, family)
			return nil, fmt.Errorf("local-ip family IPv4 is incompatible with SDP remote media address %s", ip)
		}
		log.Printf("sip-tester: rejecting SDP destination %s:%d due to family mismatch local-ip-family=%s", ip, port, family)
		return nil, fmt.Errorf("local-ip family IPv6 is incompatible with SDP remote media address %s", ip)
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(parsed.String(), strconv.Itoa(port)))
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return "disabled"
	}
	return addr.String()
}

func handleInfoLoop(ctx context.Context, logger *log.Logger, dialog *sipclient.Dialog) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		waitCtx, cancel := context.WithTimeout(ctx, time.Second)
		payload, err := dialog.HandleIncomingINFO(waitCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			continue
		}

		logger.Printf("handled INFO content-type=%q bytes=%d", payload.ContentType, len(payload.Body))
	}
}
