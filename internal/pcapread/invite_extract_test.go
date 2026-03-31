package pcapread

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sip-tester/internal/pcapio"
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
	body := "v=0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	headers := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	pkts := []Packet{
		{
			Decoded: pcapio.DecodedPacket{IsTCP: true, Payload: []byte(headers + body[:10])},
			Raw:     pcapio.Packet{Data: []byte(headers + body[:10])},
		},
		{
			Raw: pcapio.Packet{Data: []byte(body[10:])},
		},
	}

	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if sdp != strings.TrimSpace(body) {
		t.Fatalf("assembled sdp=%q want=%q", sdp, strings.TrimSpace(body))
	}
}

func TestFindFirstInviteWithSDPAcrossPacketsWithFragmentDecodeError(t *testing.T) {
	body := "v=0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	headers := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	pkts := []Packet{
		{
			Decoded: pcapio.DecodedPacket{IsTCP: true, Payload: []byte(headers + body[:14])},
			Raw:     pcapio.Packet{Data: []byte(headers + body[:14])},
		},
		{
			Raw:       pcapio.Packet{Data: []byte(body[14:])},
			DecodeErr: errors.New("ipv4 fragment offset unsupported"),
		},
	}

	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	if sdp != strings.TrimSpace(body) {
		t.Fatalf("assembled sdp=%q want=%q", sdp, strings.TrimSpace(body))
	}
}

func TestFindFirstInviteWithSDPUsesNextConsecutivePacketData(t *testing.T) {
	headers := "INVITE sip:bob@example.com SIP/2.0\r\nContent-Type: application/sdp\r\nContent-Length: 20\r\n\r\n"
	part1 := "v=0\r\nm=audio "
	part2 := "4000 RTP/AVP 0\r\n\x00\x00\x00\x00"
	pkts := []Packet{
		{
			Decoded: pcapio.DecodedPacket{IsTCP: true, Payload: []byte(headers + part1)},
			Raw:     pcapio.Packet{Data: []byte(headers + part1)},
		},
		{
			Raw: pcapio.Packet{Data: []byte(part2)},
		},
	}

	sdp, err := FindFirstInviteWithSDP(pkts)
	if err != nil {
		t.Fatalf("FindFirstInviteWithSDP error = %v", err)
	}
	want := strings.TrimSpace((part1 + part2)[:20])
	if sdp != want {
		t.Fatalf("assembled sdp=%q want=%q", sdp, want)
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
