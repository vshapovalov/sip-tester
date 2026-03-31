package pcapio

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func ReadAll(path string) ([]Packet, CaptureInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, CaptureInfo{}, fmt.Errorf("cannot open pcap %q: %w", path, err)
	}
	defer f.Close()

	br := bufio.NewReader(f)
	peek, err := br.Peek(4)
	if err != nil {
		return nil, CaptureInfo{}, fmt.Errorf("cannot read file header: %w", err)
	}

	if bytes.Equal(peek, []byte{0x0A, 0x0D, 0x0D, 0x0A}) {
		return readPCAPNG(br)
	}
	return readPCAP(br)
}

func readFull(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func u16(b []byte, order binary.ByteOrder) uint16 { return order.Uint16(b) }
func u32(b []byte, order binary.ByteOrder) uint32 { return order.Uint32(b) }
