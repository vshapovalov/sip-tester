package app

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"sip-tester/internal/pcapio"
)

func TestRunStreamSignalingReplaysAudioAndVideoOverUDP(t *testing.T) {
	// Run logs to process-wide stdout, so these log-capturing subtests must stay sequential.
	for _, scenario := range []struct {
		name       string
		transport  string
		isInsecure bool
	}{
		{name: "TCP", transport: "tcp"},
		{name: "TLS with explicit CA", transport: "tls"},
		{name: "TLS with insecure opt in", transport: "tls", isInsecure: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			capturePath, expectedAudio, expectedVideo := writeRunTransportPCAP(t)
			audioReceiver := listenRunTransportRTP(t)
			videoReceiver := listenRunTransportRTP(t)
			tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tcpListener.Close() })
			if err := tcpListener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var listener net.Listener = tcpListener
			arguments := runTransportArguments(capturePath, listener.Addr().String(), scenario.transport)
			if scenario.transport == "tls" {
				serverTLS, caPath := createRunTransportTLSCertificate(t)
				listener = tls.NewListener(listener, serverTLS)
				if scenario.isInsecure {
					arguments = append(arguments, "--tls-insecure")
				} else {
					host := net.JoinHostPort("localhost", strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port))
					arguments = runTransportArguments(capturePath, host, scenario.transport)
					arguments = append(arguments, "--tls-ca-file", caPath)
				}
			}
			peerDone := make(chan error, 1)
			go func() {
				peerDone <- serveRunTransportCall(listener, scenario.transport, audioReceiver.LocalAddr().(*net.UDPAddr).Port, videoReceiver.LocalAddr().(*net.UDPAddr).Port)
			}()
			logs, runErr := runCapturingTransportLogs(t, arguments)
			peerErr := <-peerDone
			if runErr != nil || peerErr != nil {
				t.Fatalf("Run error=%v; SIP peer error=%v\n%s", runErr, peerErr, logs)
			}
			hasInsecureWarning := strings.Contains(logs, "WARNING: SIP TLS certificate verification disabled by --tls-insecure")
			if hasInsecureWarning != scenario.isInsecure {
				t.Fatalf("insecure warning=%t, want %t\n%s", hasInsecureWarning, scenario.isInsecure, logs)
			}
			assertRunTransportRTP(t, audioReceiver, expectedAudio)
			assertRunTransportRTP(t, videoReceiver, expectedVideo)
		})
	}
}

func TestRunRejectsUnreadableTLSCAFile(t *testing.T) {
	capturePath, _, _ := writeRunTransportPCAP(t)
	arguments := runTransportArguments(capturePath, "127.0.0.1:5061", "tls")
	arguments = append(arguments, "--tls-ca-file", filepath.Join(t.TempDir(), "missing-ca.pem"))
	err := Run(arguments)
	if err == nil || !strings.Contains(err.Error(), "configure SIP TLS: read TLS CA file") {
		t.Fatalf("Run error=%v, want explicit TLS configuration failure", err)
	}
}

func runTransportArguments(capturePath, host, transport string) []string {
	return []string{
		"--caller", "1001", "--callee", "1002", "--host", host,
		"--local-ip", "127.0.0.1", "--pcap", capturePath,
		"--ssrc-audio", "0x11223344", "--ssrc-video", "0x55667788", "--transport", transport,
	}
}

func serveRunTransportCall(listener net.Listener, transport string, audioPort, videoPort int) error {
	connection, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept SIP connection: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(connection)
	for _, expectedMethod := range []string{"INVITE", "ACK", "BYE"} {
		request, err := readRunTransportRequest(reader)
		if err != nil {
			return fmt.Errorf("read %s: %w", expectedMethod, err)
		}
		if request.Method != expectedMethod {
			return fmt.Errorf("received %s, want %s", request.Method, expectedMethod)
		}
		if !strings.HasPrefix(request.GetHeader("Via"), "SIP/2.0/"+strings.ToUpper(transport)+" ") {
			return fmt.Errorf("%s has incorrect transport in Via: %q", expectedMethod, request.GetHeader("Via"))
		}
		if request.Method == "ACK" {
			continue
		}
		headers := make(map[string]string)
		for _, headerName := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
			headers[headerName] = request.GetHeader(headerName)
		}
		response := &sip.Response{StatusCode: 200, Reason: "OK", Headers: headers}
		if request.Method == "INVITE" {
			if !strings.Contains(request.GetHeader("Contact"), ";transport="+transport) {
				return fmt.Errorf("INVITE has incorrect Contact transport: %q", request.GetHeader("Contact"))
			}
			if !strings.Contains(request.Body, " RTP/AVP 0\r\n") || !strings.Contains(request.Body, " RTP/AVP 96\r\n") {
				return fmt.Errorf("INVITE does not offer plain audio/video RTP: %q", request.Body)
			}
			headers["To"] += ";tag=run-transport-peer"
			headers["Contact"] = "<sip:1002@" + listener.Addr().String() + ";transport=" + transport + ">"
			headers["Content-Type"] = "application/sdp"
			response.Body = fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\nm=video %d RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n", audioPort, videoPort)
		}
		if _, err := connection.Write(sip.BuildResponse(response)); err != nil {
			return fmt.Errorf("respond to %s: %w", expectedMethod, err)
		}
	}
	return nil
}

func readRunTransportRequest(reader *bufio.Reader) (*sip.Request, error) {
	var headers strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		headers.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	request, _, err := sip.ParseMessage([]byte(headers.String()))
	if err != nil || request == nil {
		return nil, fmt.Errorf("invalid SIP request: %v", err)
	}
	contentLength, err := strconv.Atoi(request.GetHeader("Content-Length"))
	if err != nil || contentLength < 0 {
		return nil, fmt.Errorf("invalid Content-Length: %q", request.GetHeader("Content-Length"))
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	request.Body = string(body)
	return request, nil
}

func listenRunTransportRTP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return connection
}

func assertRunTransportRTP(t *testing.T, connection *net.UDPConn, expectedPackets [][]byte) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1500)
	for _, expectedPacket := range expectedPackets {
		packetLength, sender, err := connection.ReadFromUDP(packet)
		if err != nil {
			t.Fatalf("receive replayed UDP RTP: %v", err)
		}
		if !sender.IP.Equal(net.ParseIP("127.0.0.1")) || !bytes.Equal(packet[:packetLength], expectedPacket) {
			t.Fatalf("RTP from %s=%x, want loopback UDP payload %x", sender, packet[:packetLength], expectedPacket)
		}
	}
}

func runCapturingTransportLogs(t *testing.T, arguments []string) (string, error) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "run-output-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	originalStdout := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = originalStdout }()
	runErr := Run(arguments)
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	logs, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(logs), runErr
}

func createRunTransportTLSCertificate(t *testing.T) (*tls.Config, string) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "run-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}},
	}, caPath
}

func writeRunTransportPCAP(t *testing.T) (string, [][]byte, [][]byte) {
	t.Helper()
	audioPackets := [][]byte{
		{0x80, 0, 0, 1, 0, 0, 0, 160, 0x11, 0x22, 0x33, 0x44, 0xaa},
		{0x80, 0, 0, 2, 0, 0, 1, 64, 0x11, 0x22, 0x33, 0x44, 0xbb},
	}
	videoPackets := [][]byte{
		{0x80, 96, 0, 1, 0, 0, 14, 16, 0x55, 0x66, 0x77, 0x88, 0xcc},
		{0x80, 96, 0, 2, 0, 0, 28, 32, 0x55, 0x66, 0x77, 0x88, 0xdd},
	}
	invite := sip.BuildRequest(&sip.Request{
		Method: "INVITE", URI: "sip:1002@127.0.0.1",
		Headers: map[string]string{"Content-Type": "application/sdp"},
		Body:    "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 12000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\nm=video 12002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
	})
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], pcapio.LinkTypeRaw)
	capture := bytes.NewBuffer(header)
	for _, payload := range [][]byte{invite, audioPackets[0], audioPackets[1], videoPackets[0], videoPackets[1]} {
		packet := make([]byte, 28+len(payload))
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], []byte{127, 0, 0, 1})
		copy(packet[16:20], []byte{127, 0, 0, 2})
		binary.BigEndian.PutUint16(packet[20:22], 5060)
		binary.BigEndian.PutUint16(packet[22:24], 5060)
		binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
		copy(packet[28:], payload)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:4], 100)
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(packet)))
		binary.LittleEndian.PutUint32(record[12:16], uint32(len(packet)))
		capture.Write(record)
		capture.Write(packet)
	}
	capturePath := filepath.Join(t.TempDir(), "synthetic-call.pcap")
	if err := os.WriteFile(capturePath, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return capturePath, audioPackets, videoPackets
}
