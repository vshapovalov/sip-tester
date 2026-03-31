package replay

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"
)

const (
	minMediaPort = 10000
	maxMediaPort = 20000
)

// BindMediaSockets binds two RTP sockets (audio and video) on localIP using the provided UDP network.
func BindMediaSockets(network string, localIP net.IP) (audioConn net.PacketConn, videoConn net.PacketConn, audioPort int, videoPort int, err error) {
	if localIP == nil {
		return nil, nil, 0, 0, fmt.Errorf("local IP is required")
	}

	audioConn, audioPort, err = bindOnePort(network, localIP, nil)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	videoConn, videoPort, err = bindOnePort(network, localIP, map[int]struct{}{audioPort: {}})
	if err != nil {
		_ = audioConn.Close()
		return nil, nil, 0, 0, err
	}

	return audioConn, videoConn, audioPort, videoPort, nil
}

func bindOnePort(network string, localIP net.IP, excluded map[int]struct{}) (net.PacketConn, int, error) {
	ports := make([]int, 0, maxMediaPort-minMediaPort+1)
	for p := minMediaPort; p <= maxMediaPort; p++ {
		if _, blocked := excluded[p]; blocked {
			continue
		}
		ports = append(ports, p)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })

	for _, port := range ports {
		addr := net.JoinHostPort(localIP.String(), strconv.Itoa(port))
		conn, err := net.ListenPacket(network, addr)
		if err == nil {
			return conn, port, nil
		}
	}

	return nil, 0, fmt.Errorf("failed to bind UDP socket on %s in range %d-%d", localIP.String(), minMediaPort, maxMediaPort)
}
