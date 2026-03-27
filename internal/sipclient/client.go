package sipclient

import (
	"context"
	"fmt"
	"log"
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
	username   string
	password   string
}

type InviteResult struct {
	ToHeader  string
	SDPAnswer SDPAnswer
}

func NewClient(localIP net.IP, remoteHost string, remotePort uint16, username, password string) (*Client, error) {
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
		username:   username,
		password:   password,
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) Invite(ctx context.Context, fromURI, toURI, offerSDP string) (*Dialog, error) {
	res, err := c.SendInvite(ctx, fromURI, toURI, offerSDP)
	if err != nil {
		return nil, err
	}

	if err := c.SendACK(fromURI, toURI, res.ToHeader); err != nil {
		return nil, fmt.Errorf("send ACK: %w", err)
	}

	return c.NewDialog(fromURI, toURI, res.ToHeader, res.SDPAnswer), nil
}

func (c *Client) SendInvite(ctx context.Context, fromURI, toURI, offerSDP string) (InviteResult, error) {
	invite := c.buildInvite(fromURI, toURI, offerSDP, nil)
	if err := c.write(invite); err != nil {
		return InviteResult{}, fmt.Errorf("send INVITE: %w", err)
	}

	resp, err := c.waitForResponse(ctx)
	if err != nil {
		return InviteResult{}, fmt.Errorf("wait INVITE response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 407 {
		if !c.hasCredentials() {
			return InviteResult{}, fmt.Errorf("INVITE authentication required (%d) but --username/--password were not provided", resp.StatusCode)
		}
		return c.retryInviteWithAuth(ctx, fromURI, toURI, offerSDP, resp)
	}
	if resp.StatusCode != 200 {
		return InviteResult{}, fmt.Errorf("INVITE failed with %d %s", resp.StatusCode, resp.Reason)
	}

	return inviteResultFromResponse(resp)
}

func (c *Client) retryInviteWithAuth(ctx context.Context, fromURI, toURI, offerSDP string, challengeResp *sip.Response) (InviteResult, error) {
	log.Printf("sipclient: auth challenge received status=%d", challengeResp.StatusCode)
	challenge, authHeaderName, err := parseDigestChallengeFromResponse(challengeResp)
	if err != nil {
		return InviteResult{}, fmt.Errorf("parse digest challenge: %w", err)
	}
	selectedQOP, err := SelectDigestQOP(challenge)
	if err != nil {
		return InviteResult{}, err
	}

	log.Printf("sipclient: auth scheme=%s header=%s realm=%q algorithm=%q qop=%q", challenge.Scheme, authHeaderName, challenge.Realm, challenge.Algorithm, selectedQOP)

	c.cseq++
	cnonce := ""
	nc := ""
	if selectedQOP != "" {
		cnonce = randomToken(16)
		nc = "00000001"
	}

	authValue, err := BuildDigestAuthorizationValue(DigestAuthParams{
		Username:  c.username,
		Password:  c.password,
		Method:    "INVITE",
		URI:       toURI,
		Challenge: challenge,
		CNonce:    cnonce,
		NC:        nc,
	})
	if err != nil {
		return InviteResult{}, fmt.Errorf("build digest auth: %w", err)
	}

	headers := map[string]string{authHeaderName: authValue}
	invite := c.buildInvite(fromURI, toURI, offerSDP, headers)
	log.Printf("sipclient: authenticated INVITE retry started cseq=%d", c.cseq)
	if err := c.write(invite); err != nil {
		return InviteResult{}, fmt.Errorf("send authenticated INVITE: %w", err)
	}

	resp, err := c.waitForResponse(ctx)
	if err != nil {
		return InviteResult{}, fmt.Errorf("wait authenticated INVITE response: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 407 {
		log.Printf("sipclient: authenticated INVITE retry failed status=%d", resp.StatusCode)
		return InviteResult{}, fmt.Errorf("repeated authentication failure after retry: %d %s", resp.StatusCode, resp.Reason)
	}
	if resp.StatusCode != 200 {
		log.Printf("sipclient: authenticated INVITE retry failed status=%d", resp.StatusCode)
		return InviteResult{}, fmt.Errorf("authenticated INVITE failed with %d %s", resp.StatusCode, resp.Reason)
	}
	log.Printf("sipclient: authenticated INVITE retry succeeded")
	return inviteResultFromResponse(resp)
}

func parseDigestChallengeFromResponse(resp *sip.Response) (DigestChallenge, string, error) {
	if resp.StatusCode == 401 {
		raw := resp.Headers["WWW-Authenticate"]
		if raw == "" {
			return DigestChallenge{}, "", fmt.Errorf("auth enabled but 401 response did not include a usable WWW-Authenticate challenge")
		}
		ch, err := ParseDigestChallenge(raw, false)
		if err != nil {
			return DigestChallenge{}, "", err
		}
		return ch, "Authorization", nil
	}
	if resp.StatusCode == 407 {
		raw := resp.Headers["Proxy-Authenticate"]
		if raw == "" {
			return DigestChallenge{}, "", fmt.Errorf("auth enabled but 407 response did not include a usable Proxy-Authenticate challenge")
		}
		ch, err := ParseDigestChallenge(raw, true)
		if err != nil {
			return DigestChallenge{}, "", err
		}
		return ch, "Proxy-Authorization", nil
	}
	return DigestChallenge{}, "", fmt.Errorf("response %d is not an auth challenge", resp.StatusCode)
}

func inviteResultFromResponse(resp *sip.Response) (InviteResult, error) {
	sdpAnswer, err := ParseSDPAnswer(resp.Body)
	if err != nil {
		return InviteResult{}, fmt.Errorf("parse SDP answer: %w", err)
	}

	return InviteResult{ToHeader: resp.Headers["To"], SDPAnswer: sdpAnswer}, nil
}

func (c *Client) buildInvite(fromURI, toURI, offerSDP string, extraHeaders map[string]string) *sip.Request {
	branch := "z9hG4bK-" + randomToken(9)
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=%s;rport", c.localAddr.String(), branch),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", fromURI, c.localTag),
		"To":           fmt.Sprintf("<%s>", toURI),
		"Call-ID":      c.callID,
		"CSeq":         fmt.Sprintf("%d INVITE", c.cseq),
		"Contact":      fmt.Sprintf("<%s>", fromURI),
		"Content-Type": "application/sdp",
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return &sip.Request{Method: "INVITE", URI: toURI, Headers: headers, Body: offerSDP}
}

func (c *Client) SendACK(fromURI, toURI, toHeader string) error {
	return c.sendACK(fromURI, toURI, toHeader)
}

func (c *Client) NewDialog(fromURI, toURI, remoteTo string, sdpAnswer SDPAnswer) *Dialog {
	d := &Dialog{
		client:    c,
		fromURI:   fromURI,
		toURI:     toURI,
		remoteTo:  remoteTo,
		sdpAnswer: sdpAnswer,
	}
	return d
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

func (c *Client) hasCredentials() bool {
	return c.username != "" && c.password != ""
}
