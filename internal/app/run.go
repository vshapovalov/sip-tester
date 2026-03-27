package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"sip-tester/internal/cli"
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

	logger.Printf("resolve host: %s", cfg.Host)
	resolvedHost, err := resolveHost(cfg.Host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	logger.Printf("resolved host %s -> %s", cfg.Host, resolvedHost)

	logger.Printf("load PCAP: %s", cfg.PCAP)
	packets, err := pcapread.LoadPCAP(cfg.PCAP)
	if err != nil {
		return fmt.Errorf("load PCAP: %w", err)
	}

	logger.Println("extract streams")
	streams := pcapread.ExtractRTPBySSRC(packets)
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
	offer, err := sdp.BuildOffer(cfg.LocalIPParsed, media)
	if err != nil {
		return fmt.Errorf("build SDP offer: %w", err)
	}

	client, err := sipclient.NewClient(cfg.LocalIPParsed, resolvedHost, cfg.Port, cfg.Username, cfg.Password)
	if err != nil {
		return fmt.Errorf("create SIP client: %w", err)
	}
	defer client.Close()

	rtpStore := &replay.MediaDestinationStore{}
	replayController := newReplayController(logger, cfg.LocalIPParsed, schedule, rtpStore)

	ctx, cancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer cancel()

	logger.Println("send INVITE")
	inviteRes, err := client.SendInviteWithEarlyMedia(ctx, cfg.Caller, cfg.Callee, offer, func(answer sipclient.SDPAnswer) error {
		logger.Println("early SDP detected (183 Session Progress)")
		earlyDest, err := destinationFromAnswer(answer, replay.MediaStateEarly, false)
		if err != nil {
			return fmt.Errorf("183 SDP handling failed: %w", err)
		}
		rtpStore.Set(earlyDest)
		logger.Printf("early media destination audio=%s video=%s", udpAddrString(earlyDest.AudioAddr), udpAddrString(earlyDest.VideoAddr))
		if replayController.Start() {
			logger.Println("early media started")
		} else {
			logger.Println("early destination updated")
		}
		return nil
	})
	if err != nil {
		return err
	}
	logger.Println("200 OK received")

	logger.Println("send ACK")
	if err := client.SendACK(cfg.Caller, inviteRes); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	if !replayController.Started() {
		logger.Println("start RTP replay")
		replayController.Start()
	}

	finalDest, err := destinationFromAnswer(inviteRes.SDPAnswer, replay.MediaStateFinal, true)
	if err != nil {
		return fmt.Errorf("200 OK SDP handling failed: %w", err)
	}
	rtpStore.Set(finalDest)
	logger.Printf("final destination applied audio=%s video=%s", udpAddrString(finalDest.AudioAddr), udpAddrString(finalDest.VideoAddr))

	dialog := client.NewDialog(cfg.Caller, cfg.Callee, inviteRes)

	logger.Println("handle INFO")
	infoCtx, infoCancel := context.WithCancel(context.Background())
	go handleInfoLoop(infoCtx, logger, dialog)

	replayController.Wait()
	infoCancel()

	if err := replayController.Err(); err != nil {
		return fmt.Errorf("RTP replay: %w", err)
	}

	byeCtx, byeCancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer byeCancel()
	logger.Println("send BYE")
	if err := dialog.Bye(byeCtx); err != nil {
		return fmt.Errorf("send BYE: %w", err)
	}

	logger.Println("exit")
	return nil
}

type replayRunner struct {
	logger   *log.Logger
	localIP  net.IP
	schedule []replay.ScheduledPacket
	store    *replay.MediaDestinationStore
	mu       sync.Mutex
	started  bool
	wg       sync.WaitGroup
	err      error
	errSet   bool
}

func newReplayController(logger *log.Logger, localIP net.IP, schedule []replay.ScheduledPacket, store *replay.MediaDestinationStore) *replayRunner {
	return &replayRunner{logger: logger, localIP: localIP, schedule: schedule, store: store}
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
	conn, err := net.ListenPacket("udp", net.JoinHostPort(r.localIP.String(), "0"))
	if err != nil {
		r.setErr(err)
		return
	}
	defer conn.Close()

	sender := replay.NewUDPSender(conn, r.store)
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

func resolveHost(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for host")
	}
	return ips[0].String(), nil
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

func destinationFromAnswer(answer sipclient.SDPAnswer, state replay.MediaState, enforceUsable bool) (replay.MediaDestination, error) {
	dest := replay.MediaDestination{State: state}
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
			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", m.Port)))
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
			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", m.Port)))
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
