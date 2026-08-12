package replay

import (
	"net"
	"testing"
)

func TestBindMediaSockets(t *testing.T) {
	audioConn, videoConn, audioPort, videoPort, err := BindMediaSockets("udp4", net.ParseIP("127.0.0.1"), false)
	if err != nil {
		t.Fatalf("BindMediaSockets returned error: %v", err)
	}
	defer audioConn.Close()
	defer videoConn.Close()

	if audioConn == nil || videoConn == nil {
		t.Fatalf("expected non-nil sockets")
	}
	if audioPort < minMediaPort || audioPort > maxMediaPort {
		t.Fatalf("audio port out of range: %d", audioPort)
	}
	if videoPort < minMediaPort || videoPort > maxMediaPort {
		t.Fatalf("video port out of range: %d", videoPort)
	}
	if audioPort == videoPort {
		t.Fatalf("ports must be distinct")
	}
}

func TestBindMediaSocketsBundleUsesOneSocketAndPort(t *testing.T) {
	audioConn, videoConn, audioPort, videoPort, err := BindMediaSockets("udp4", net.ParseIP("127.0.0.1"), true)
	if err != nil {
		t.Fatalf("BindMediaSockets returned error: %v", err)
	}
	defer audioConn.Close()

	if audioConn != videoConn {
		t.Fatal("bundled media must share one socket")
	}
	if audioPort != videoPort {
		t.Fatalf("bundled ports differ: audio=%d video=%d", audioPort, videoPort)
	}
}
