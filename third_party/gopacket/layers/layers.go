package layers

type UDP struct {
	Payload []byte
}

type TCP struct {
	Payload []byte
}

type LinkType int

const (
	LinkTypeEthernet LinkType = 1
	LinkTypeRaw      LinkType = 101
)

type LayerType int

const (
	LayerTypeUDP LayerType = 17
	LayerTypeTCP LayerType = 6
)
