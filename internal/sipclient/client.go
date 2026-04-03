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
	"sip-tester/internal/netutil"
)

const readBufferSize = 64 * 1024

type Client struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	localAddr  *net.UDPAddr
	registrar  string
	callID     string
	localTag   string
	cseq       int
	username   string
	password   string
	userAgent  string
}

type InviteResult struct {
	ToHeader     string
	RemoteTag    string
	RemoteTarget string
	RouteSet     []string
	SDPAnswer    SDPAnswer
}

type EarlyMediaHandler func(SDPAnswer) error

func NewClient(localIP net.IP, family netutil.IPFamily, target netutil.ResolvedTarget, username, password, userAgent string) (*Client, error) {
	if localIP == nil {
		return nil, fmt.Errorf("local IP is required")
	}
	network, err := netutil.UDPNetworkForFamily(family)
	if err != nil {
		return nil, err
	}
	remoteAddr, err := net.ResolveUDPAddr(network, target.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote address: %w", err)
	}

	localAddr := &net.UDPAddr{IP: localIP, Port: 0}
	conn, err := net.ListenUDP(network, localAddr)
	if err != nil {
		return nil, fmt.Errorf("bind local UDP socket %s: %w", localIP.String(), err)
	}

	bound := conn.LocalAddr().(*net.UDPAddr)

	return &Client{
		conn:       conn,
		remoteAddr: remoteAddr,
		localAddr:  bound,
		registrar:  net.JoinHostPort(target.Hostname, fmt.Sprintf("%d", target.Port)),
		callID:     randomToken(12),
		localTag:   randomToken(8),
		cseq:       1,
		username:   username,
		password:   password,
		userAgent:  fallbackUserAgent(userAgent),
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) LocalAddr() *net.UDPAddr {
	return c.localAddr
}

func (c *Client) Invite(ctx context.Context, fromURI, toURI, offerSDP string) (*Dialog, error) {
	res, err := c.SendInvite(ctx, fromURI, toURI, offerSDP)
	if err != nil {
		return nil, err
	}

	if err := c.SendACK(fromURI, res); err != nil {
		return nil, fmt.Errorf("send ACK: %w", err)
	}

	return c.NewDialog(fromURI, toURI, res), nil
}

func (c *Client) SendInvite(ctx context.Context, fromURI, toURI, offerSDP string) (InviteResult, error) {
	return c.sendInvite(ctx, fromURI, toURI, offerSDP, nil)
}

func (c *Client) SendInviteWithEarlyMedia(ctx context.Context, fromURI, toURI, offerSDP string, earlyHandler EarlyMediaHandler) (InviteResult, error) {
	return c.sendInvite(ctx, fromURI, toURI, offerSDP, earlyHandler)
}

func (c *Client) sendInvite(ctx context.Context, fromURI, toURI, offerSDP string, earlyHandler EarlyMediaHandler) (InviteResult, error) {
	invite := c.buildInvite(fromURI, toURI, offerSDP, nil)
	if err := c.write(invite); err != nil {
		return InviteResult{}, fmt.Errorf("send INVITE: %w", err)
	}

	resp, err := c.waitForInviteResponse(ctx, earlyHandler)
	if err != nil {
		return InviteResult{}, fmt.Errorf("wait INVITE response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 407 {
		if !c.hasCredentials() {
			return InviteResult{}, fmt.Errorf("INVITE authentication required (%d) but --username/--password were not provided", resp.StatusCode)
		}
		return c.retryInviteWithAuth(ctx, fromURI, toURI, offerSDP, resp, earlyHandler)
	}
	if resp.StatusCode != 200 {
		return InviteResult{}, fmt.Errorf("INVITE failed with %d %s", resp.StatusCode, resp.Reason)
	}

	return inviteResultFromResponse(resp)
}

func (c *Client) retryInviteWithAuth(ctx context.Context, fromURI, toURI, offerSDP string, challengeResp *sip.Response, earlyHandler EarlyMediaHandler) (InviteResult, error) {
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

	resp, err := c.waitForInviteResponse(ctx, earlyHandler)
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
		raw := resp.GetHeader("WWW-Authenticate")
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
		raw := resp.GetHeader("Proxy-Authenticate")
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
	sdpAnswer, err := ParseSDP(resp.Body)
	if err != nil {
		return InviteResult{}, fmt.Errorf("parse SDP answer: %w", err)
	}

	toHeader := resp.GetHeader("To")
	remoteTag := extractTag(toHeader)
	remoteTarget, err := parseNameAddrTarget(resp.GetHeader("Contact"))
	if err != nil {
		return InviteResult{}, fmt.Errorf("parse Contact as remote target: %w", err)
	}
	routeSet := buildRouteSetForUAC(parseHeaderURIList(resp.HeaderValues("Record-Route")))

	log.Printf("sipclient: dialog created call-id=%s local-tag=%s remote-tag=%s", resp.GetHeader("Call-ID"), extractTag(resp.GetHeader("From")), remoteTag)
	log.Printf("sipclient: remote target=%s", remoteTarget)
	log.Printf("sipclient: route set=%v", routeSet)

	return InviteResult{
		ToHeader:     toHeader,
		RemoteTag:    remoteTag,
		RemoteTarget: remoteTarget,
		RouteSet:     routeSet,
		SDPAnswer:    sdpAnswer,
	}, nil
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
		"User-Agent":   c.userAgent,
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return &sip.Request{Method: "INVITE", URI: toURI, Headers: headers, Body: offerSDP}
}

func (c *Client) SendACK(fromURI string, inviteRes InviteResult) error {
	ack := c.buildACK(fromURI, inviteRes)
	log.Printf("sipclient: ACK destination request-uri=%s routes=%v", ack.URI, inviteRes.RouteSet)
	return c.write(ack)
}

func (c *Client) NewDialog(fromURI, toURI string, inviteRes InviteResult) *Dialog {
	d := &Dialog{
		client:       c,
		fromURI:      fromURI,
		toURI:        toURI,
		remoteTo:     inviteRes.ToHeader,
		remoteTag:    inviteRes.RemoteTag,
		remoteTarget: inviteRes.RemoteTarget,
		routeSet:     append([]string(nil), inviteRes.RouteSet...),
		sdpAnswer:    inviteRes.SDPAnswer,
	}
	return d
}

func (c *Client) buildACK(fromURI string, inviteRes InviteResult) *sip.Request {
	ack := &sip.Request{
		Method: "ACK",
		URI:    inviteRes.RemoteTarget,
		Headers: map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", c.localAddr.String(), randomToken(9)),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", fromURI, c.localTag),
			"To":           inviteRes.ToHeader,
			"Call-ID":      c.callID,
			"CSeq":         fmt.Sprintf("%d ACK", c.cseq),
			"Contact":      fmt.Sprintf("<%s>", fromURI),
			"User-Agent":   c.userAgent,
		},
	}
	if len(inviteRes.RouteSet) > 0 {
		ack.Headers["Route"] = strings.Join(inviteRes.RouteSet, ", ")
	}
	return ack
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
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			continue
		}
		return resp, nil
	}
}

func (c *Client) waitForInviteResponse(ctx context.Context, earlyHandler EarlyMediaHandler) (*sip.Response, error) {
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
			if require100Rel(resp.GetHeader("Require")) {
				return nil, fmt.Errorf("100rel/PRACK not supported")
			}
			switch resp.StatusCode {
			case 100:
				log.Printf("sipclient: received 100 Trying")
			case 180:
				log.Printf("sipclient: received 180 Ringing")
			case 183:
				log.Printf("sipclient: received 183 Session Progress")
				if strings.TrimSpace(resp.Body) == "" {
					log.Printf("sipclient: 183 has no SDP, continuing")
					continue
				}
				sdpAnswer, err := ParseSDPAnswer(resp.Body)
				if err != nil {
					return nil, fmt.Errorf("parse SDP in 183: %w", err)
				}
				if earlyHandler != nil {
					if err := earlyHandler(sdpAnswer); err != nil {
						return nil, err
					}
				}
			default:
				log.Printf("sipclient: received provisional %d %s", resp.StatusCode, resp.Reason)
			}
			continue
		}
		return resp, nil
	}
}

func require100Rel(rawRequire string) bool {
	for _, item := range strings.Split(rawRequire, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "100rel") {
			return true
		}
	}
	return false
}

func fallbackUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return "sip-tester"
	}
	return userAgent
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

func buildRouteSetForUAC(recordRoutes []string) []string {
	if len(recordRoutes) == 0 {
		return nil
	}
	routeSet := make([]string, 0, len(recordRoutes))
	for i := len(recordRoutes) - 1; i >= 0; i-- {
		routeSet = append(routeSet, recordRoutes[i])
	}
	return routeSet
}

func buildRouteSetForUAS(recordRoutes []string) []string {
	if len(recordRoutes) == 0 {
		return nil
	}
	return append([]string(nil), recordRoutes...)
}

func parseHeaderURIList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	routes := make([]string, 0, len(values))
	for _, raw := range values {
		for _, p := range strings.Split(raw, ",") {
			route := strings.TrimSpace(p)
			if route == "" {
				continue
			}
			routes = append(routes, route)
		}
	}
	return routes
}

func parseNameAddrTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty header")
	}
	if lt := strings.IndexByte(raw, '<'); lt >= 0 {
		gt := strings.IndexByte(raw[lt:], '>')
		if gt < 0 {
			return "", fmt.Errorf("malformed name-addr %q", raw)
		}
		return strings.TrimSpace(raw[lt+1 : lt+gt]), nil
	}
	if semi := strings.IndexByte(raw, ';'); semi >= 0 {
		return strings.TrimSpace(raw[:semi]), nil
	}
	return raw, nil
}
