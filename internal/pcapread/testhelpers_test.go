package pcapread

import (
	"encoding/binary"
	"net"
	"os"
	"time"
)

func buildEtherIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{6, 7, 8, 9, 10, 11})
	copy(eth[6:12], []byte{0, 1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	out := append(append(append([]byte{}, eth...), ip...), udp...)
	return append(out, payload...)
}

func buildEtherIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{6, 7, 8, 9, 10, 11})
	copy(eth[6:12], []byte{0, 1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	out := append(append(append([]byte{}, eth...), ip...), tcp...)
	return append(out, payload...)
}

func writeClassicPCAP(path string, linkType uint32, ts time.Time, frames ...[]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], 65535)
	binary.LittleEndian.PutUint32(h[20:24], linkType)
	if _, err := f.Write(h); err != nil {
		return err
	}
	for i, fr := range frames {
		rh := make([]byte, 16)
		t := ts.Add(time.Duration(i) * time.Millisecond)
		binary.LittleEndian.PutUint32(rh[0:4], uint32(t.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(t.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(fr)))
		if _, err := f.Write(rh); err != nil {
			return err
		}
		if _, err := f.Write(fr); err != nil {
			return err
		}
	}
	return nil
}

func buildRTPPayload(ssrc uint32, seq uint16, ts uint32) []byte {
	p := make([]byte, 12)
	p[0] = 0x80
	p[1] = 96
	binary.BigEndian.PutUint16(p[2:4], seq)
	binary.BigEndian.PutUint32(p[4:8], ts)
	binary.BigEndian.PutUint32(p[8:12], ssrc)
	return p
}
