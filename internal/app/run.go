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

	ctx, cancel := context.WithTimeout(context.Background(), defaultStepTimeout)
	defer cancel()

	logger.Println("send INVITE")
	inviteRes, err := client.SendInvite(ctx, cfg.Caller, cfg.Callee, offer)
	if err != nil {
		return err
	}
	logger.Println("receive 200 OK")

	logger.Println("send ACK")
	if err := client.SendACK(cfg.Caller, inviteRes); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	dialog := client.NewDialog(cfg.Caller, cfg.Callee, inviteRes)

	rtpCtx, rtpCancel := context.WithCancel(context.Background())
	defer rtpCancel()
	var wg sync.WaitGroup

	logger.Println("start RTP replay")
	replayErrs := make(chan error, 2)
	startReplay(rtpCtx, &wg, replayErrs, cfg.LocalIPParsed, inviteRes.SDPAnswer, audioStream, videoStream)

	logger.Println("handle INFO")
	infoCtx, infoCancel := context.WithCancel(context.Background())
	go handleInfoLoop(infoCtx, logger, dialog)

	wg.Wait()
	infoCancel()

	select {
	case err := <-replayErrs:
		if err != nil {
			return fmt.Errorf("RTP replay: %w", err)
		}
	default:
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

func startReplay(ctx context.Context, wg *sync.WaitGroup, replayErrs chan<- error, localIP net.IP, answer sipclient.SDPAnswer, audio, video []pcapread.RTPPacket) {
	for _, m := range answer.Media {
		if m.Type == "audio" && len(audio) > 0 {
			startReplayForMedia(ctx, wg, replayErrs, localIP, answer.ConnectionIP, m.Port, audio)
		}
		if m.Type == "video" && len(video) > 0 {
			startReplayForMedia(ctx, wg, replayErrs, localIP, answer.ConnectionIP, m.Port, video)
		}
	}
}

func startReplayForMedia(ctx context.Context, wg *sync.WaitGroup, replayErrs chan<- error, localIP net.IP, remoteIP string, remotePort int, packets []pcapread.RTPPacket) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		schedule := replay.BuildSchedule(packets, nil)
		if len(schedule) == 0 {
			return
		}

		conn, err := net.ListenPacket("udp", net.JoinHostPort(localIP.String(), "0"))
		if err != nil {
			replayErrs <- err
			return
		}
		defer conn.Close()

		remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(remoteIP, fmt.Sprintf("%d", remotePort)))
		if err != nil {
			replayErrs <- err
			return
		}

		sender := replay.NewUDPSender(conn, remoteAddr)
		if err := sender.Replay(ctx, schedule); err != nil && !errors.Is(err, context.Canceled) {
			replayErrs <- err
		}
	}()
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
