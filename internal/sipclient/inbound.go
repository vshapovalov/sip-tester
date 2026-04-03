package sipclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

type InboundDialog struct {
	client       *Client
	fromURI      string
	toURI        string
	callID       string
	localTag     string
	remoteTag    string
	remoteTo     string
	remoteTarget string
	routeSet     []string
}

func BuildRegisterContact(aor string, localAddr *net.UDPAddr) (string, error) {
	if localAddr == nil || localAddr.IP == nil {
		return "", fmt.Errorf("local SIP socket address is required")
	}
	user := strings.TrimPrefix(strings.TrimSpace(aor), "sip:")
	if at := strings.Index(user, "@"); at >= 0 {
		user = user[:at]
	}
	if user == "" {
		return "", fmt.Errorf("invalid AoR for Contact")
	}
	host := localAddr.IP.String()
	host = formatSIPURIHost(host)
	return fmt.Sprintf("sip:%s@%s:%d", user, host, localAddr.Port), nil
}

func formatSIPURIHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func buildRegisterURI(registrar string) (string, error) {
	registrar = strings.TrimSpace(registrar)
	if registrar == "" {
		return "", fmt.Errorf("registrar host is required")
	}

	host := registrar
	port := ""
	if strings.Contains(registrar, ":") {
		if h, p, err := net.SplitHostPort(registrar); err == nil {
			host = h
			port = p
		}
	}

	host = formatSIPURIHost(host)
	if port != "" {
		return fmt.Sprintf("sip:%s:%s", host, port), nil
	}
	return "sip:" + host, nil
}

func (c *Client) Register(ctx context.Context, aor string, contact string, expires int) error {
	registerURI, err := buildRegisterURI(c.registrar)
	if err != nil {
		return fmt.Errorf("build REGISTER request-uri: %w", err)
	}
	callID := randomToken(12)
	fromTag := randomToken(8)
	cseq := 1
	buildReq := func(extra map[string]string) *sip.Request {
		headers := map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", c.localAddr.String(), randomToken(9)),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", aor, fromTag),
			"To":           fmt.Sprintf("<%s>", aor),
			"Call-ID":      callID,
			"CSeq":         fmt.Sprintf("%d REGISTER", cseq),
			"Contact":      fmt.Sprintf("<%s>", contact),
			"Expires":      strconv.Itoa(expires),
		}
		for k, v := range extra {
			headers[k] = v
		}
		return &sip.Request{Method: "REGISTER", URI: registerURI, Headers: headers}
	}
	if err := c.write(buildReq(nil)); err != nil {
		return fmt.Errorf("send REGISTER: %w", err)
	}
	resp, err := c.waitForResponse(ctx)
	if err != nil {
		return fmt.Errorf("wait REGISTER response: %w", err)
	}
	if resp.StatusCode == 200 {
		return nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		return fmt.Errorf("REGISTER failed with %d %s", resp.StatusCode, resp.Reason)
	}
	if !c.hasCredentials() {
		return fmt.Errorf("REGISTER authentication required (%d) but --username/--password were not provided", resp.StatusCode)
	}
	challenge, authHeaderName, err := parseDigestChallengeFromResponse(resp)
	if err != nil {
		return fmt.Errorf("parse REGISTER challenge: %w", err)
	}
	selectedQOP, err := SelectDigestQOP(challenge)
	if err != nil {
		return err
	}
	cseq++
	cnonce := ""
	nc := ""
	if selectedQOP != "" {
		cnonce = randomToken(16)
		nc = "00000001"
	}
	authValue, err := BuildDigestAuthorizationValue(DigestAuthParams{
		Username:  c.username,
		Password:  c.password,
		Method:    "REGISTER",
		URI:       registerURI,
		Challenge: challenge,
		CNonce:    cnonce,
		NC:        nc,
	})
	if err != nil {
		return fmt.Errorf("build REGISTER digest auth: %w", err)
	}
	if err := c.write(buildReq(map[string]string{authHeaderName: authValue})); err != nil {
		return fmt.Errorf("send authenticated REGISTER: %w", err)
	}
	resp, err = c.waitForResponse(ctx)
	if err != nil {
		return fmt.Errorf("wait authenticated REGISTER response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("authenticated REGISTER failed with %d %s", resp.StatusCode, resp.Reason)
	}
	return nil
}

func (c *Client) WaitForInvite(ctx context.Context) (*sip.Request, *net.UDPAddr, error) {
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.conn.SetReadDeadline(deadline)
		} else {
			_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		buf := make([]byte, readBufferSize)
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				default:
					return nil, nil, fmt.Errorf("SIP request timeout")
				}
			}
			return nil, nil, err
		}
		req, _, err := sip.ParseMessage(buf[:n])
		if err != nil || req == nil || req.Method != "INVITE" {
			continue
		}
		return req, addr, nil
	}
}

func (c *Client) NewInboundDialog(invite *sip.Request, localURI string) (*InboundDialog, error) {
	remoteTarget, err := parseNameAddrTarget(invite.Headers["Contact"])
	if err != nil {
		return nil, fmt.Errorf("parse Contact as remote target: %w", err)
	}
	localTag := randomToken(8)
	return &InboundDialog{
		client:       c,
		fromURI:      localURI,
		toURI:        parseNameAddrToURI(invite.Headers["From"]),
		callID:       invite.Headers["Call-ID"],
		localTag:     localTag,
		remoteTag:    extractTag(invite.Headers["From"]),
		remoteTo:     invite.Headers["From"],
		remoteTarget: remoteTarget,
		routeSet:     buildRouteSetForUAS(parseHeaderURIList(invite.Headers["Record-Route"])),
	}, nil
}

func parseNameAddrToURI(raw string) string {
	uri, err := parseNameAddrTarget(raw)
	if err != nil {
		return ""
	}
	return uri
}

func (d *InboundDialog) inviteToWithLocalTag(invite *sip.Request) string {
	base := strings.TrimSpace(invite.Headers["To"])
	if base == "" {
		base = fmt.Sprintf("<%s>", d.fromURI)
	}
	if strings.Contains(base, ";tag=") {
		return base
	}
	return base + ";tag=" + d.localTag
}

func (d *InboundDialog) SendInviteResponse(invite *sip.Request, addr *net.UDPAddr, code int, reason string, body string, contentType string) error {
	headers := map[string]string{
		"Via":     invite.Headers["Via"],
		"From":    invite.Headers["From"],
		"To":      d.inviteToWithLocalTag(invite),
		"Call-ID": invite.Headers["Call-ID"],
		"CSeq":    invite.Headers["CSeq"],
	}
	if invite.Method == "INVITE" && code == 200 {
		contact, err := BuildRegisterContact(d.fromURI, d.client.localAddr)
		if err != nil {
			return fmt.Errorf("build Contact for INVITE response: %w", err)
		}
		headers["Contact"] = fmt.Sprintf("<%s>", contact)
	}
	if body != "" {
		headers["Content-Type"] = contentType
	}
	resp := &sip.Response{StatusCode: code, Reason: reason, Headers: headers, Body: body}
	_, err := d.client.conn.WriteToUDP(sip.BuildResponse(resp), addr)
	return err
}

func (d *InboundDialog) WaitForACK(ctx context.Context) error {
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = d.client.conn.SetReadDeadline(deadline)
		} else {
			_ = d.client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		buf := make([]byte, readBufferSize)
		n, _, err := d.client.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return fmt.Errorf("ACK timeout")
				}
			}
			return err
		}
		req, _, err := sip.ParseMessage(buf[:n])
		if err != nil || req == nil || req.Method != "ACK" {
			continue
		}
		if d.matchesRequestDialog(req) {
			return nil
		}
	}
}

func (d *InboundDialog) HandleIncomingRequest(ctx context.Context) (string, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = d.client.conn.SetReadDeadline(deadline)
	} else {
		_ = d.client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	buf := make([]byte, readBufferSize)
	n, addr, err := d.client.conn.ReadFromUDP(buf)
	if err != nil {
		return "", err
	}
	req, _, err := sip.ParseMessage(buf[:n])
	if err != nil || req == nil {
		return "", fmt.Errorf("invalid request")
	}
	if !d.matchesRequestDialog(req) {
		return "", fmt.Errorf("request did not match dialog")
	}
	switch req.Method {
	case "INFO", "BYE":
		resp := &sip.Response{StatusCode: 200, Reason: "OK", Headers: map[string]string{
			"Via": req.Headers["Via"], "From": req.Headers["From"], "To": req.Headers["To"], "Call-ID": req.Headers["Call-ID"], "CSeq": req.Headers["CSeq"],
		}}
		_, err = d.client.conn.WriteToUDP(sip.BuildResponse(resp), addr)
		if err != nil {
			return "", err
		}
		return req.Method, nil
	default:
		return "", fmt.Errorf("unsupported method %s", req.Method)
	}
}

func (d *InboundDialog) Bye(ctx context.Context) error {
	d.client.cseq++
	bye := d.buildByeRequest()
	if err := d.client.write(bye); err != nil {
		return fmt.Errorf("send BYE: %w", err)
	}
	resp, err := d.client.waitForResponse(ctx)
	if err != nil {
		return fmt.Errorf("wait BYE response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("BYE failed with %d %s", resp.StatusCode, resp.Reason)
	}
	return nil
}

func (d *InboundDialog) buildByeRequest() *sip.Request {
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.localTag),
		"To":           d.remoteTo,
		"Call-ID":      d.callID,
		"CSeq":         fmt.Sprintf("%d BYE", d.client.cseq),
	}
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	return &sip.Request{Method: "BYE", URI: d.remoteTarget, Headers: headers}
}

func (d *InboundDialog) matchesRequestDialog(req *sip.Request) bool {
	if req.Headers["Call-ID"] != d.callID {
		return false
	}
	if extractTag(req.Headers["From"]) != d.remoteTag {
		return false
	}
	return extractTag(req.Headers["To"]) == d.localTag
}
