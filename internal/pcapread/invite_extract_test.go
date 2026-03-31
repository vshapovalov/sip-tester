package pcapread

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFindFirstInviteWithSDPFromTransportPayload(t *testing.T) {
	dir := t.TempDir()
	sdpBody := "v=0\r\n"
	invite := []byte("INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(sdpBody)) + "\r\n\r\n" + sdpBody)
	udp := buildEtherIPv4UDP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, invite)
	tcp := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n"))
	path := filepath.Join(dir, "invite.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), tcp, udp); err != nil {
		t.Fatal(err)
	}

	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if !strings.Contains(sdp, "v=0") {
		t.Fatalf("sdp=%q", sdp)
	}
}

func TestFindFirstInviteWithSDPAcrossConsecutivePacketsSameFlow(t *testing.T) {
	dir := t.TempDir()
	body := "v=0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	headers := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	frame1 := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte(headers+body[:10]))
	frame2 := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte(body[10:]))
	path := filepath.Join(dir, "split-invite.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), frame1, frame2); err != nil {
		t.Fatal(err)
	}

	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if sdp != strings.TrimSpace(body) {
		t.Fatalf("assembled sdp=%q want=%q", sdp, strings.TrimSpace(body))
	}
}

func TestFindFirstInviteWithSDPIgnoresDifferentFlowContinuation(t *testing.T) {
	dir := t.TempDir()
	headers := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: 20\r\n\r\n"
	part1 := "v=0\r\nm=audio "
	part2WrongFlow := "4000 RTP/AVP 0\r\n"
	frame1 := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte(headers+part1))
	frame2 := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 9), net.IPv4(10, 0, 0, 10), 5070, 5070, []byte(part2WrongFlow))
	path := filepath.Join(dir, "split-other-flow.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), frame1, frame2); err != nil {
		t.Fatal(err)
	}

	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FindFirstInviteWithSDP(pkts)
	if !errors.Is(err, ErrSDPNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrSDPNotFound)
	}
}

func TestFindFirstInviteWithSDPErrInviteNotFound(t *testing.T) {
	dir := t.TempDir()
	non := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"))
	path := filepath.Join(dir, "no-invite.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), non); err != nil {
		t.Fatal(err)
	}
	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FindFirstInviteWithSDP(pkts)
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrInviteNotFound)
	}
}

func TestFindFirstInviteWithSDPErrSDPNotFound(t *testing.T) {
	dir := t.TempDir()
	inviteNoBody := []byte("INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	frame := buildEtherIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, inviteNoBody)
	path := filepath.Join(dir, "invite-no-sdp.pcap")
	if err := writeClassicPCAP(path, 1, time.Unix(1, 0), frame); err != nil {
		t.Fatal(err)
	}
	pkts, err := LoadPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FindFirstInviteWithSDP(pkts)
	if !errors.Is(err, ErrSDPNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrSDPNotFound)
	}
}
