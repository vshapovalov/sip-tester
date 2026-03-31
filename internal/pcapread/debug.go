package pcapread

import "fmt"

func BuildPacketDiagnostics(linkType uint32, packets []Packet, sampleSize int) []string {
	if sampleSize < 0 {
		sampleSize = 0
	}
	if sampleSize > len(packets) {
		sampleSize = len(packets)
	}
	out := make([]string, 0, sampleSize+1)
	out = append(out, fmt.Sprintf("pcap link type: %d", linkType))
	for i := 0; i < sampleSize; i++ {
		p := packets[i]
		errTxt := "none"
		if p.DecodeErr != nil {
			errTxt = p.DecodeErr.Error()
		}
		out = append(out, fmt.Sprintf("packet #%d ts=%s link=%d ip=%d %s:%d -> %s:%d proto=%d payload=%d decode_err=%s", i+1, p.Raw.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"), p.Raw.LinkType, p.Decoded.IPVersion, p.Decoded.SrcIP, p.Decoded.SrcPort, p.Decoded.DstIP, p.Decoded.DstPort, p.Decoded.Protocol, len(p.Decoded.Payload), errTxt))
	}
	return out
}
