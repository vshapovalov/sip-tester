package sipclient

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// streamSocket exposes complete SIP messages on a persistent TCP/TLS connection.
// Replies and subsequent requests reuse the outbound proxy connection, regardless
// of the dialog's Request-URI or the address passed to WriteTo.
type streamSocket struct {
	net.Conn
	pending []byte
	readErr error
	writeMu sync.Mutex
}

func (s *streamSocket) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		// RFC 3261 section 7.5 permits CRLF before a stream message.
		for bytes.HasPrefix(s.pending, []byte("\r\n")) {
			s.pending = s.pending[2:]
		}
		length, err := sipStreamMessageLength(s.pending)
		if err != nil {
			s.Close()
			return 0, nil, err
		}
		if length > 0 && len(s.pending) >= length {
			if len(packet) < length {
				return 0, nil, io.ErrShortBuffer
			}
			copy(packet, s.pending[:length])
			s.pending = s.pending[length:]
			return length, s.RemoteAddr(), nil
		}
		if s.readErr != nil {
			err := s.readErr
			s.readErr = nil
			if err == io.EOF && len(s.pending) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
		fragment := make([]byte, min(4096, readBufferSize-len(s.pending)))
		count, err := s.Conn.Read(fragment)
		s.pending = append(s.pending, fragment[:count]...)
		s.readErr = err
	}
}

// A zero length means the header is incomplete, not a message with an empty body.
func sipStreamMessageLength(pending []byte) (int, error) {
	headerEnd := bytes.Index(pending, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		if len(pending) >= readBufferSize {
			return 0, fmt.Errorf("SIP stream header exceeds %d bytes", readBufferSize)
		}
		return 0, nil
	}
	contentLength := -1
	unfoldedHeaders := strings.NewReplacer("\r\n ", " ", "\r\n\t", " ").Replace(string(pending[:headerEnd]))
	for _, header := range strings.Split(unfoldedHeaders, "\r\n")[1:] {
		name, rawLength, found := strings.Cut(header, ":")
		if !found || (!strings.EqualFold(strings.TrimSpace(name), "Content-Length") && !strings.EqualFold(strings.TrimSpace(name), "l")) {
			continue
		}
		if contentLength >= 0 {
			return 0, fmt.Errorf("duplicate SIP stream Content-Length")
		}
		rawLength = strings.TrimSpace(rawLength)
		if rawLength == "" || strings.IndexFunc(rawLength, func(character rune) bool { return character < '0' || character > '9' }) >= 0 {
			return 0, fmt.Errorf("invalid SIP stream Content-Length")
		}
		parsedLength, err := strconv.ParseUint(rawLength, 10, 32)
		if err != nil || parsedLength > uint64(readBufferSize-headerEnd-4) {
			return 0, fmt.Errorf("SIP stream message exceeds %d bytes", readBufferSize)
		}
		contentLength = int(parsedLength)
	}
	if contentLength < 0 {
		return 0, fmt.Errorf("SIP stream message requires Content-Length")
	}
	return headerEnd + 4 + contentLength, nil
}

func (s *streamSocket) WriteTo(packet []byte, _ net.Addr) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return 0, err
	}
	written := 0
	for written < len(packet) {
		count, err := s.Conn.Write(packet[written:])
		written += count
		if err != nil {
			s.Close()
			return written, err
		}
		if count == 0 {
			s.Close()
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
