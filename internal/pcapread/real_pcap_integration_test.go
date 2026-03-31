package pcapread

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type expectedRTPStream struct {
	SSRC        uint32
	MediaLabel  string
	PacketCount *int
	PayloadType *uint8
}

func TestLoadPCAP_RealFile(t *testing.T) {
	pcapPath, _ := mustFindRealCaptureFiles(t)

	packets, err := LoadPCAP(pcapPath)
	if err != nil {
		t.Fatalf("LoadPCAP(%q) returned error: %v", pcapPath, err)
	}
	if len(packets) == 0 {
		t.Fatalf("LoadPCAP(%q) returned no packets", pcapPath)
	}

	withNetworkLayer, withTransportLayer := countDecodedLayers(packets)
	if withNetworkLayer == 0 {
		t.Fatalf("no packets in %q decoded a network layer", pcapPath)
	}
	if withTransportLayer == 0 {
		t.Fatalf("no packets in %q decoded a transport layer", pcapPath)
	}
}

func TestExtractRTPStreams_RealPCAP(t *testing.T) {
	pcapPath, csvPath := mustFindRealCaptureFiles(t)
	expected := loadExpectedStreamsFromCSV(t, csvPath)

	packets, err := LoadPCAP(pcapPath)
	if err != nil {
		t.Fatalf("LoadPCAP(%q) returned error: %v", pcapPath, err)
	}

	streams := ExtractRTPBySSRC(packets)
	if len(streams) == 0 {
		t.Fatalf("ExtractRTPBySSRC returned no streams for %q", pcapPath)
	}
	if len(streams) < len(expected) {
		t.Fatalf("expected at least %d streams from CSV %q, got %d", len(expected), csvPath, len(streams))
	}

	ptToMedia, codecToMedia := extractMediaHints(t, packets)

	for _, exp := range expected {
		ssrc := exp.SSRC
		pkts, ok := streams[ssrc]
		if !ok {
			t.Fatalf("expected SSRC %s from CSV was not found in parsed streams", formatSSRC(ssrc))
		}
		if len(pkts) == 0 {
			t.Fatalf("parsed RTP stream for SSRC %s is empty", formatSSRC(ssrc))
		}

		for i := 1; i < len(pkts); i++ {
			if pkts[i].CaptureTime.Before(pkts[i-1].CaptureTime) {
				t.Fatalf("RTP stream for SSRC %s is not sorted by capture time at index %d: %s before %s", formatSSRC(ssrc), i, pkts[i].CaptureTime.Format(time.RFC3339Nano), pkts[i-1].CaptureTime.Format(time.RFC3339Nano))
			}
		}

		if exp.PacketCount != nil && len(pkts) != *exp.PacketCount {
			t.Fatalf("packet count mismatch for SSRC %s: got %d, expected %d from CSV", formatSSRC(ssrc), len(pkts), *exp.PacketCount)
		}

		if exp.PayloadType != nil && pkts[0].PayloadType != *exp.PayloadType {
			t.Fatalf("payload type mismatch for SSRC %s: first parsed payload type=%d, expected=%d from CSV", formatSSRC(ssrc), pkts[0].PayloadType, *exp.PayloadType)
		}

		if expectedMedia := classifyMediaLabel(exp.MediaLabel); expectedMedia != "" {
			ptMedia := strings.ToLower(ptToMedia[pkts[0].PayloadType])
			if ptMedia == "" {
				codecMedia := strings.ToLower(codecToMedia[strings.ToLower(exp.MediaLabel)])
				if codecMedia != "" {
					ptMedia = codecMedia
				}
			}
			if ptMedia != "" && ptMedia != expectedMedia {
				t.Fatalf("media classification mismatch for SSRC %s: expected %s based on CSV label %q, got %s from SDP-derived hints", formatSSRC(ssrc), expectedMedia, exp.MediaLabel, ptMedia)
			}
		}
	}
}

func TestExtractInviteSDP_RealPCAP(t *testing.T) {
	pcapPath, _ := mustFindRealCaptureFiles(t)
	packets, err := LoadPCAP(pcapPath)
	if err != nil {
		t.Fatalf("LoadPCAP(%q) returned error: %v", pcapPath, err)
	}

	rawSDP, err := FindFirstInviteWithSDP(packets)
	if err != nil {
		t.Fatalf("INVITE SDP not found in real PCAP %q: %v", pcapPath, err)
	}

	media, err := ParseSDPMedia(rawSDP)
	if err != nil {
		t.Fatalf("ParseSDPMedia failed for SDP extracted from %q: %v", pcapPath, err)
	}
	if len(media) == 0 {
		t.Fatalf("expected at least one SDP media section in INVITE from %q", pcapPath)
	}

	mediaSeen := map[string]bool{}
	for _, m := range media {
		mediaSeen[strings.ToLower(m.Media)] = true
	}

	if len(mediaSeen) == 1 {
		if !mediaSeen["audio"] && !mediaSeen["video"] {
			t.Fatalf("unexpected SDP media sections in INVITE from %q: %+v", pcapPath, media)
		}
	} else {
		if !mediaSeen["audio"] || !mediaSeen["video"] {
			t.Fatalf("expected both audio and video in INVITE SDP from %q when multiple media sections exist, got %+v", pcapPath, media)
		}
	}
}

func mustFindRealCaptureFiles(t *testing.T) (pcapPath, csvPath string) {
	t.Helper()

	testdataDir := filepath.Join("..", "..", "testdata")
	entries, err := os.ReadDir(testdataDir)
	if err != nil {
		t.Fatalf("failed to read testdata directory %q: %v", testdataDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(testdataDir, entry.Name())
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		switch ext {
		case ".pcap":
			if pcapPath != "" {
				t.Fatalf("multiple pcap files found in %q: %q and %q; expected exactly one", testdataDir, pcapPath, fullPath)
			}
			pcapPath = fullPath
		case ".csv":
			if csvPath != "" {
				t.Fatalf("multiple csv files found in %q: %q and %q; expected exactly one stream metadata csv", testdataDir, csvPath, fullPath)
			}
			csvPath = fullPath
		}
	}

	if pcapPath == "" {
		t.Fatalf("no .pcap file found in %q", testdataDir)
	}
	if csvPath == "" {
		t.Fatalf("no .csv stream metadata file found in %q", testdataDir)
	}
	return pcapPath, csvPath
}

func loadExpectedStreamsFromCSV(t *testing.T, csvPath string) []expectedRTPStream {
	t.Helper()

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("failed to open expected streams CSV %q: %v", csvPath, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV %q: %v", csvPath, err)
	}
	if len(records) < 2 {
		t.Fatalf("CSV %q must include header and at least one data row", csvPath)
	}

	headerIndex := make(map[string]int, len(records[0]))
	for i, h := range records[0] {
		headerIndex[normalizeHeader(h)] = i
	}

	ssrcIdx := firstExistingColumn(headerIndex, "ssrc", "ssrc_formatted", "ssrcformatted")
	if ssrcIdx < 0 {
		t.Fatalf("CSV %q is missing required SSRC column; looked for one of: ssrc, ssrc formatted", csvPath)
	}

	packetsIdx := firstExistingColumn(headerIndex, "packets", "packet_count", "packetcount")
	payloadTypeIdx := firstExistingColumn(headerIndex, "payload_type", "payloadtype", "pt")
	mediaIdx := firstExistingColumn(headerIndex, "media", "media_type", "mediatype", "payload", "codec")
	altSSRCIdx := firstExistingColumn(headerIndex, "ssrc_formatted", "ssrcformatted")

	expected := make([]expectedRTPStream, 0, len(records)-1)
	for rowIdx, row := range records[1:] {
		get := func(col int) string {
			if col < 0 || col >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[col])
		}

		primarySSRC := get(ssrcIdx)
		if primarySSRC == "" && altSSRCIdx >= 0 {
			primarySSRC = get(altSSRCIdx)
		}
		if primarySSRC == "" {
			continue
		}

		ssrc, err := normalizeSSRC(primarySSRC)
		if err != nil {
			if altSSRCIdx >= 0 {
				if alt := get(altSSRCIdx); alt != "" {
					ssrc, err = normalizeSSRC(alt)
				}
			}
			if err != nil {
				t.Fatalf("invalid SSRC value at CSV row %d in %q: %q (%v)", rowIdx+2, csvPath, primarySSRC, err)
			}
		}

		stream := expectedRTPStream{SSRC: ssrc}

		if mediaIdx >= 0 {
			stream.MediaLabel = get(mediaIdx)
		}

		if packetsIdx >= 0 {
			v := get(packetsIdx)
			if v != "" {
				count, err := strconv.Atoi(v)
				if err != nil {
					t.Fatalf("invalid packet count at CSV row %d in %q: %q (%v)", rowIdx+2, csvPath, v, err)
				}
				stream.PacketCount = &count
			}
		}

		if payloadTypeIdx >= 0 {
			v := get(payloadTypeIdx)
			if v != "" {
				n, err := strconv.ParseUint(v, 10, 8)
				if err != nil {
					t.Fatalf("invalid payload type at CSV row %d in %q: %q (%v)", rowIdx+2, csvPath, v, err)
				}
				pt := uint8(n)
				stream.PayloadType = &pt
			}
		}

		expected = append(expected, stream)
	}

	if len(expected) == 0 {
		t.Fatalf("CSV %q produced zero expected RTP streams", csvPath)
	}

	return expected
}

func extractMediaHints(t *testing.T, packets []Packet) (map[uint8]string, map[string]string) {
	t.Helper()
	ptToMedia := map[uint8]string{}
	codecToMedia := map[string]string{}

	rawSDP, err := FindFirstInviteWithSDP(packets)
	if err != nil {
		return ptToMedia, codecToMedia
	}

	media, err := ParseSDPMedia(rawSDP)
	if err != nil {
		return ptToMedia, codecToMedia
	}

	for _, section := range media {
		for _, pt := range section.PayloadTypes {
			if pt < 0 || pt > 255 {
				continue
			}
			ptToMedia[uint8(pt)] = section.Media
		}
		for pt, rtpmap := range section.RTPMap {
			if pt >= 0 && pt <= 255 {
				ptToMedia[uint8(pt)] = section.Media
			}
			codec := strings.ToLower(strings.TrimSpace(strings.SplitN(rtpmap, "/", 2)[0]))
			if codec != "" {
				codecToMedia[codec] = section.Media
			}
		}
	}

	return ptToMedia, codecToMedia
}

func normalizeSSRC(raw string) (uint32, error) {
	v := strings.TrimSpace(strings.Trim(raw, `"`))
	if v == "" {
		return 0, fmt.Errorf("empty SSRC")
	}

	n, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func normalizeHeader(h string) string {
	h = strings.TrimSpace(strings.Trim(h, `"`))
	h = strings.ToLower(h)
	h = strings.ReplaceAll(h, "-", "_")
	h = strings.ReplaceAll(h, " ", "_")
	return h
}

func firstExistingColumn(headers map[string]int, candidates ...string) int {
	for _, c := range candidates {
		if idx, ok := headers[c]; ok {
			return idx
		}
	}
	return -1
}

func formatSSRC(ssrc uint32) string {
	return fmt.Sprintf("%d (0x%08x)", ssrc, ssrc)
}

func classifyMediaLabel(label string) string {
	v := strings.ToLower(strings.TrimSpace(label))
	switch {
	case v == "audio", strings.Contains(v, "g711"), strings.Contains(v, "pcmu"), strings.Contains(v, "pcma"), strings.Contains(v, "opus"), strings.Contains(v, "g722"):
		return "audio"
	case v == "video", strings.Contains(v, "h264"), strings.Contains(v, "h265"), strings.Contains(v, "vp8"), strings.Contains(v, "vp9"):
		return "video"
	default:
		return ""
	}
}

func countDecodedLayers(packets []Packet) (withNetworkLayer, withTransportLayer int) {
	for _, packet := range packets {
		if packet.DecodeErr != nil {
			continue
		}
		if packet.Decoded.IPVersion != 0 {
			withNetworkLayer++
		}
		if packet.Decoded.IsUDP || packet.Decoded.IsTCP {
			withTransportLayer++
		}
	}
	return withNetworkLayer, withTransportLayer
}
