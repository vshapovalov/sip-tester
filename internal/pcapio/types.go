package pcapio

import (
	"net"
	"time"
)

const (
	LinkTypeNull      uint32 = 0
	LinkTypeEthernet  uint32 = 1
	LinkTypeRaw       uint32 = 12
	LinkTypeLinuxSLL  uint32 = 113
	LinkTypeLinuxSLL2 uint32 = 276
)

type FileFormat string

const (
	FormatPCAP   FileFormat = "pcap"
	FormatPCAPNG FileFormat = "pcapng"
)

type Packet struct {
	Timestamp time.Time
	Data      []byte
	LinkType  uint32
}

type CaptureInfo struct {
	Format    FileFormat
	LinkTypes []uint32
	Count     int
}

type DecodedPacket struct {
	Timestamp time.Time
	LinkType  uint32

	EtherType uint16
	IPVersion int
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  uint8
	SrcPort   uint16
	DstPort   uint16
	IsUDP     bool
	IsTCP     bool
	Payload   []byte
}
