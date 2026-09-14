package sipclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"sip-tester/internal/netutil"
)

type TransportOptions struct {
	Protocol  string
	TLSConfig *tls.Config
}

func openSignalingSocket(localIP net.IP, family netutil.IPFamily, target netutil.ResolvedTarget, options TransportOptions) (net.PacketConn, net.Addr, error) {
	network, err := netutil.UDPNetworkForFamily(family)
	if err != nil {
		return nil, nil, err
	}
	if options.Protocol == "udp" {
		remoteAddress, err := net.ResolveUDPAddr(network, target.RemoteAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve remote address: %w", err)
		}
		socket, err := net.ListenUDP(network, &net.UDPAddr{IP: localIP})
		if err != nil {
			return nil, nil, fmt.Errorf("bind local UDP socket %s: %w", localIP, err)
		}
		return socket, remoteAddress, nil
	}
	if options.Protocol != "tcp" && options.Protocol != "tls" {
		return nil, nil, fmt.Errorf("unsupported SIP transport %q", options.Protocol)
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: localIP}, Timeout: 15 * time.Second}
	network = strings.Replace(network, "udp", "tcp", 1)
	var connection net.Conn
	if options.Protocol == "tls" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if options.TLSConfig != nil {
			tlsConfig = options.TLSConfig.Clone()
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = target.Hostname
		}
		connection, err = tls.DialWithDialer(dialer, network, target.RemoteAddr, tlsConfig)
	} else {
		connection, err = dialer.Dial(network, target.RemoteAddr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("connect SIP %s to %s: %w", options.Protocol, target.RemoteAddr, err)
	}
	return &streamSocket{Conn: connection}, connection.RemoteAddr(), nil
}

func (c *Client) via(branch string) string {
	protocol := c.transport
	if protocol == "" {
		protocol = "udp"
	}
	return fmt.Sprintf("SIP/2.0/%s %s;branch=%s;rport", strings.ToUpper(protocol), c.localAddr.String(), branch)
}

func (c *Client) Contact(aor string) (string, error) {
	contact, err := BuildRegisterContact(aor, c.localAddr)
	if err != nil {
		return "", err
	}
	return c.contactTransport(contact), nil
}

func (c *Client) contactTransport(uri string) string {
	if c.transport == "tcp" || c.transport == "tls" {
		return uri + ";transport=" + c.transport
	}
	return uri
}

func (c *Client) inviteContact(fromURI string) string {
	if c.transport != "tcp" && c.transport != "tls" {
		return fromURI
	}
	return c.contactTransport(fmt.Sprintf("sip:%s@%s", sipURIUser(fromURI), c.localAddr.String()))
}
