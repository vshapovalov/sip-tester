package sipclient

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStreamSocketFramesFragmentedAndCoalescedMessages(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	socket := &streamSocket{Conn: client}
	first := "SIP/2.0 200 OK\r\nContent-Length: 8\r\n\r\na\r\n\r\nbcd"
	second := "SIP/2.0 180 Ringing\r\nl:\r\n\t0\r\n\r\n"
	written := make(chan error, 1)
	go func() {
		for _, fragment := range []string{"\r", "\n\r\n" + first[:19], first[19 : len(first)-2], first[len(first)-2:] + second} {
			if _, err := io.WriteString(server, fragment); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	for _, want := range []string{first, second} {
		packet := make([]byte, readBufferSize)
		socket.SetReadDeadline(time.Now().Add(time.Second))
		length, sender, err := socket.ReadFrom(packet)
		if err != nil {
			t.Fatal(err)
		}
		if string(packet[:length]) != want || sender.String() != server.LocalAddr().String() {
			t.Fatalf("received %q from %v", packet[:length], sender)
		}
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestStreamSocketRejectsInvalidFraming(t *testing.T) {
	for _, headers := range []string{
		"", "Content-Length: -1\r\n", "Content-Length: +1\r\n", "Content-Length: x\r\n",
		"Content-Length: 1\r\nl: 2\r\n", "Content-Length: 0\r\nContent-Length: 0\r\n",
		"Content-Length: 65536\r\n", "X-Fill: " + strings.Repeat("a", readBufferSize),
	} {
		t.Run(headers[:min(len(headers), 45)], func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			go func() { io.WriteString(server, "SIP/2.0 200 OK\r\n"+headers+"\r\n"); server.Close() }()
			socket := &streamSocket{Conn: client}
			if _, _, err := socket.ReadFrom(make([]byte, readBufferSize)); err == nil {
				t.Fatal("accepted invalid stream framing")
			}
		})
	}
}

func TestStreamSocketRetainsPartialMessageAfterTimeout(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	socket := &streamSocket{Conn: client}
	go func() {
		io.WriteString(server, "SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nab")
		client.SetReadDeadline(time.Now().Add(-time.Second))
	}()
	packet := make([]byte, readBufferSize)
	if _, _, err := socket.ReadFrom(packet); err == nil {
		t.Fatal("expected timeout")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	go func() { io.WriteString(server, "cd") }()
	socket.SetReadDeadline(time.Now().Add(time.Second))
	length, _, err := socket.ReadFrom(packet)
	if err != nil || !bytes.HasSuffix(packet[:length], []byte("abcd")) {
		t.Fatalf("partial body lost: %q, %v", packet[:length], err)
	}
}

func TestStreamSocketDeliversFinalMessageBeforeEOF(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	want := "SIP/2.0 200 OK\r\nContent-Length:\r\n 4\r\n\r\nbody"
	socket := &streamSocket{Conn: &finalReadConnection{Conn: client, packet: []byte(want)}}
	packet := make([]byte, readBufferSize)
	length, _, err := socket.ReadFrom(packet)
	if err != nil || string(packet[:length]) != want {
		t.Fatalf("last message = %q, error = %v", packet[:length], err)
	}
	if _, _, err := socket.ReadFrom(packet); !errors.Is(err, io.EOF) {
		t.Fatalf("after final message: %v", err)
	}
}

type finalReadConnection struct {
	net.Conn
	packet []byte
}

func (c *finalReadConnection) Read(packet []byte) (int, error) {
	count := copy(packet, c.packet)
	c.packet = c.packet[count:]
	return count, io.EOF
}

func TestStreamSocketWritesWholeMessageAcrossShortWrites(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	connection := &shortWriteConnection{Conn: client}
	socket := &streamSocket{Conn: connection}
	want := []byte("INVITE sip:1002@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	count, err := socket.WriteTo(want, server.LocalAddr())
	if err != nil || count != len(want) || !bytes.Equal(connection.written.Bytes(), want) {
		t.Fatalf("write = %d, %v, %q", count, err, connection.written.Bytes())
	}
}

func TestStreamSocketReportsWriteFailureAndClosesConnection(t *testing.T) {
	for _, writeErr := range []error{io.ErrClosedPipe, nil} {
		client, server := net.Pipe()
		connection := &failedWriteConnection{Conn: client, writeErr: writeErr}
		socket := &streamSocket{Conn: connection}
		_, err := socket.WriteTo([]byte("SIP message"), server.LocalAddr())
		if err == nil || !connection.closed {
			t.Fatalf("failed write: error=%v closed=%v", err, connection.closed)
		}
		server.Close()
	}
}

type failedWriteConnection struct {
	net.Conn
	writeErr error
	closed   bool
}

func (c *failedWriteConnection) Write([]byte) (int, error) { return 0, c.writeErr }
func (c *failedWriteConnection) Close() error              { c.closed = true; return c.Conn.Close() }

func TestStreamSocketPreservesMessageWhenReceiveBufferIsSmall(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	want := "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
	socket := &streamSocket{Conn: &finalReadConnection{Conn: client, packet: []byte(want)}}
	if _, _, err := socket.ReadFrom(make([]byte, 4)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("small buffer error: %v", err)
	}
	packet := make([]byte, readBufferSize)
	length, _, err := socket.ReadFrom(packet)
	if err != nil || string(packet[:length]) != want {
		t.Fatalf("retried receive: %q %v", packet[:length], err)
	}
}

func TestStreamSocketReportsWriteDeadlineFailure(t *testing.T) {
	client, server := net.Pipe()
	client.Close()
	server.Close()
	socket := &streamSocket{Conn: client}
	if _, err := socket.WriteTo([]byte("SIP message"), server.LocalAddr()); err == nil {
		t.Fatal("closed socket accepted write")
	}
}

type shortWriteConnection struct {
	net.Conn
	written bytes.Buffer
}

func (c *shortWriteConnection) Write(packet []byte) (int, error) {
	return c.written.Write(packet[:min(len(packet), 7)])
}

func TestStreamSocketReportsTruncatedMessage(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go func() { io.WriteString(server, "SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nab"); server.Close() }()
	socket := &streamSocket{Conn: client}
	if _, _, err := socket.ReadFrom(make([]byte, readBufferSize)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
}
