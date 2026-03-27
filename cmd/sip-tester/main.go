package main

import (
	"fmt"
	"os"
	"sort"

	"sip-tester/internal/cli"
	"sip-tester/internal/pcapread"
)

func main() {
	cfg, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("normalized caller: %s\n", cfg.Caller)
	fmt.Printf("normalized callee: %s\n", cfg.Callee)
	fmt.Printf("host: %s:%d\n", cfg.Host, cfg.Port)
	fmt.Printf("local-ip: %s\n", cfg.LocalIPParsed.String())
	fmt.Printf("detected IP family: %s\n", cfg.IPFamily)

	if cfg.SSRCAudio != nil {
		fmt.Printf("parsed ssrc-audio: %d (0x%08x)\n", *cfg.SSRCAudio, *cfg.SSRCAudio)
	} else {
		fmt.Println("parsed ssrc-audio: <not provided>")
	}

	if cfg.SSRCVideo != nil {
		fmt.Printf("parsed ssrc-video: %d (0x%08x)\n", *cfg.SSRCVideo, *cfg.SSRCVideo)
	} else {
		fmt.Println("parsed ssrc-video: <not provided>")
	}

	packets, err := pcapread.LoadPCAP(cfg.PCAP)
	if err != nil {
		exitErr("load pcap", err)
	}

	sdpRaw, err := pcapread.FindFirstInviteWithSDP(packets)
	if err != nil {
		exitErr("find invite", err)
	}

	sdpMedia, err := pcapread.ParseSDPMedia(sdpRaw)
	if err != nil {
		exitErr("parse sdp", err)
	}

	streams := pcapread.ExtractRTPBySSRC(packets)
	requested := requestedSSRCs(cfg.SSRCAudio, cfg.SSRCVideo)
	filtered, err := pcapread.FilterSSRC(streams, requested...)
	if err != nil {
		exitErr("filter ssrc", err)
	}

	fmt.Printf("pcap packets: %d\n", len(packets))
	fmt.Printf("pcap duration: %s\n", pcapread.CaptureDuration(packets))
	fmt.Printf("sdp media sections: %d\n", len(sdpMedia))
	for _, media := range sdpMedia {
		fmt.Printf("  %s payload-types=%v rtpmap=%d fmtp=%d\n", media.Media, media.PayloadTypes, len(media.RTPMap), len(media.FMTP))
	}

	for _, ssrc := range requested {
		pkts := filtered[ssrc]
		fmt.Printf("rtp stream 0x%08x packets=%d duration=%s\n", ssrc, len(pkts), pcapread.StreamDuration(pkts))
	}
}

func requestedSSRCs(audio, video *uint32) []uint32 {
	requested := make([]uint32, 0, 2)
	if audio != nil {
		requested = append(requested, *audio)
	}
	if video != nil {
		requested = append(requested, *video)
	}
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })
	return requested
}

func exitErr(op string, err error) {
	fmt.Fprintf(os.Stderr, "error: %s: %v\n", op, err)
	os.Exit(1)
}
