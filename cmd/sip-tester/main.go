package main

import (
	"fmt"
	"os"

	"sip-tester/internal/cli"
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
}
