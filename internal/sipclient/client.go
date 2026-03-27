package sipclient

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

const readBufferSize = 64 * 1024

type Client struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	localAddr  *net.UDPAddr
	callID     string
	localTag   string
	cseq       int
}

func NewClient(localIP net.IP, remoteHost string, remotePort uint16) (*Client, error) {
	if localIP == nil {
		return nil, fmt.Errorf("local IP is required")
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
	if err != nil {
		return nil, fmt.Errorf("resolve remote address: %w", err)
	}

	localAddr := &net.UDPAddr{IP: localIP, Port: 0}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("bind local UDP socket %s: %w", localIP.String(), err)
	}

	bound := conn.LocalAddr().(*net.UDPAddr)

	return &Client{
		conn:       conn,
		remoteAddr: remoteAddr,
		localAddr:  bound,
		callID:     randomToken(12),
		localTag:   randomToken(8),
		cseq:       1,
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) Invite(ctx context.Context, fromURI, toURI, offerSDP string) (*Dialog, error) {
	branch := "z9hG4bK-" + randomToken(9)
	invite := &sip.Request{
		Method: "INVITE",
		URI:    toURI,
		Headers: map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=%s;rport", c.localAddr.String(), branch),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", fromURI, c.localTag),
			"To":           fmt.Sprintf("<%s>", toURI),
			"Call-ID":      c.callID,
			"CSeq":         fmt.Sprintf("%d INVITE", c.cseq),
			"Contact":      fmt.Sprintf("<%s>", fromURI),
			"Content-Type": "application/sdp",
		},
		Body: offerSDP,
	}

	if err := c.write(invite); err != nil {
		return nil, fmt.Errorf("send INVITE: %w", err)
	}

	resp, err := c.waitForResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait INVITE response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("INVITE failed with %d %s", resp.StatusCode, resp.Reason)
	}

	sdpAnswer, err := ParseSDPAnswer(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse SDP answer: %w", err)
	}

	if err := c.sendACK(fromURI, toURI, resp.Headers["To"]); err != nil {
		return nil, fmt.Errorf("send ACK: %w", err)
	}

	d := &Dialog{
		client:    c,
		fromURI:   fromURI,
		toURI:     toURI,
		remoteTo:  resp.Headers["To"],
		sdpAnswer: sdpAnswer,
	}
	return d, nil
}

func (c *Client) sendACK(fromURI, toURI, toHeader string) error {
	ack := &sip.Request{
		Method: "ACK",
		URI:    toURI,
		Headers: map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", c.localAddr.String(), randomToken(9)),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", fromURI, c.localTag),
			"To":           toHeader,
			"Call-ID":      c.callID,
			"CSeq":         fmt.Sprintf("%d ACK", c.cseq),
			"Contact":      fmt.Sprintf("<%s>", fromURI),
		},
	}
	return c.write(ack)
}

func (c *Client) write(req *sip.Request) error {
	payload := sip.BuildRequest(req)
	_, err := c.conn.WriteToUDP(payload, c.remoteAddr)
	return err
}

func (c *Client) waitForResponse(ctx context.Context) (*sip.Response, error) {
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.conn.SetReadDeadline(deadline)
		} else {
			_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		buf := make([]byte, readBufferSize)
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default:
					return nil, fmt.Errorf("SIP response timeout")
				}
			}
			return nil, err
		}
		_, resp, err := sip.ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			continue
		}
		return resp, nil
	}
}

func randomToken(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i := range out {
		out[i] = chars[rand.Intn(len(chars))]
	}
	return string(out)
}

func extractTag(h string) string {
	for _, piece := range strings.Split(h, ";") {
		piece = strings.TrimSpace(piece)
		if strings.HasPrefix(piece, "tag=") {
			return strings.TrimPrefix(piece, "tag=")
		}
	}
	return ""
}
