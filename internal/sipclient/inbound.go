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
			"User-Agent":   c.userAgent,
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
	remoteTarget, err := parseNameAddrTarget(invite.GetHeader("Contact"))
	if err != nil {
		return nil, fmt.Errorf("parse Contact as remote target: %w", err)
	}
	localTag := randomToken(8)
	return &InboundDialog{
		client:       c,
		fromURI:      localURI,
		toURI:        parseNameAddrToURI(invite.GetHeader("From")),
		callID:       invite.GetHeader("Call-ID"),
		localTag:     localTag,
		remoteTag:    extractTag(invite.GetHeader("From")),
		remoteTo:     invite.GetHeader("From"),
		remoteTarget: remoteTarget,
		routeSet:     buildRouteSetForUAS(parseHeaderURIList(invite.HeaderValues("Record-Route"))),
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
	base := strings.TrimSpace(invite.GetHeader("To"))
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
		"From":       invite.GetHeader("From"),
		"To":         d.inviteToWithLocalTag(invite),
		"Call-ID":    invite.GetHeader("Call-ID"),
		"CSeq":       invite.GetHeader("CSeq"),
		"User-Agent": d.client.userAgent,
	}
	headerFields := make([]sip.Header, 0, 12)
	for _, via := range invite.HeaderValues("Via") {
		headerFields = append(headerFields, sip.Header{Name: "Via", Value: via})
	}
	headerFields = append(headerFields,
		sip.Header{Name: "From", Value: headers["From"]},
		sip.Header{Name: "To", Value: headers["To"]},
		sip.Header{Name: "Call-ID", Value: headers["Call-ID"]},
		sip.Header{Name: "CSeq", Value: headers["CSeq"]},
		sip.Header{Name: "User-Agent", Value: d.client.userAgent},
	)
	for _, rr := range invite.HeaderValues("Record-Route") {
		headerFields = append(headerFields, sip.Header{Name: "Record-Route", Value: rr})
	}
	if invite.Method == "INVITE" && code == 200 {
		contact, err := BuildRegisterContact(d.fromURI, d.client.localAddr)
		if err != nil {
			return fmt.Errorf("build Contact for INVITE response: %w", err)
		}
		headers["Contact"] = fmt.Sprintf("<%s>", contact)
		headerFields = append(headerFields, sip.Header{Name: "Contact", Value: headers["Contact"]})
	}
	if body != "" {
		headers["Content-Type"] = contentType
		headerFields = append(headerFields, sip.Header{Name: "Content-Type", Value: contentType})
	}
	resp := &sip.Response{StatusCode: code, Reason: reason, Headers: headers, HeaderFields: headerFields, Body: body}
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

func (d *InboundDialog) WaitForCancel(ctx context.Context, invite *sip.Request) (bool, error) {
	for {
		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline {
			_ = d.client.conn.SetReadDeadline(deadline)
		} else {
			_ = d.client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		buffer := make([]byte, readBufferSize)
		readCount, address, err := d.client.conn.ReadFromUDP(buffer)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() && hasDeadline {
				return false, nil
			}
			return false, err
		}
		request, _, err := sip.ParseMessage(buffer[:readCount])
		if err != nil || request == nil || request.Method != "CANCEL" || !d.cancelMatchesInvite(request, invite) {
			continue
		}
		if err := d.respondOKToRequest(request, address); err != nil {
			return false, fmt.Errorf("send 200 for CANCEL: %w", err)
		}
		return true, nil
	}
}

func (d *InboundDialog) cancelMatchesInvite(cancelRequest, invite *sip.Request) bool {
	if cancelRequest.GetHeader("Call-ID") != invite.GetHeader("Call-ID") || extractTag(cancelRequest.GetHeader("From")) != d.remoteTag {
		return false
	}
	cancelCSeq := strings.Fields(cancelRequest.GetHeader("CSeq"))
	inviteCSeq := strings.Fields(invite.GetHeader("CSeq"))
	if len(cancelCSeq) != 2 || len(inviteCSeq) != 2 || cancelCSeq[0] != inviteCSeq[0] {
		return false
	}
	toTag := extractTag(cancelRequest.GetHeader("To"))
	return toTag == "" || toTag == d.localTag
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
	case "INFO", "BYE", "CANCEL":
		if err := d.respondOKToRequest(req, addr); err != nil {
			return "", err
		}
		return req.Method, nil
	default:
		return "", fmt.Errorf("unsupported method %s", req.Method)
	}
}

func (d *InboundDialog) respondOKToRequest(request *sip.Request, address *net.UDPAddr) error {
	headerFields := make([]sip.Header, 0, 8)
	for _, via := range request.HeaderValues("Via") {
		headerFields = append(headerFields, sip.Header{Name: "Via", Value: via})
	}
	headerFields = append(headerFields,
		sip.Header{Name: "From", Value: request.GetHeader("From")},
		sip.Header{Name: "To", Value: request.GetHeader("To")},
		sip.Header{Name: "Call-ID", Value: request.GetHeader("Call-ID")},
		sip.Header{Name: "CSeq", Value: request.GetHeader("CSeq")},
		sip.Header{Name: "User-Agent", Value: d.client.userAgent},
	)
	response := &sip.Response{StatusCode: 200, Reason: "OK", Headers: map[string]string{
		"From": request.GetHeader("From"), "To": request.GetHeader("To"), "Call-ID": request.GetHeader("Call-ID"), "CSeq": request.GetHeader("CSeq"), "User-Agent": d.client.userAgent,
	}, HeaderFields: headerFields}
	_, err := d.client.conn.WriteToUDP(sip.BuildResponse(response), address)
	return err
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

func (d *InboundDialog) Reinvite(ctx context.Context, offerSDP string) (SDPAnswer, error) {
	d.client.cseq++
	reinvite, err := d.buildReinviteRequest(offerSDP)
	if err != nil {
		return SDPAnswer{}, err
	}
	if err := d.client.write(reinvite); err != nil {
		return SDPAnswer{}, fmt.Errorf("send re-INVITE: %w", err)
	}
	response, err := d.client.waitForInviteResponse(ctx, nil, reinvite, time.Time{})
	if err != nil {
		return SDPAnswer{}, fmt.Errorf("wait re-INVITE response: %w", err)
	}
	if response.StatusCode != 200 {
		return SDPAnswer{}, fmt.Errorf("re-INVITE failed with %d %s", response.StatusCode, response.Reason)
	}
	answer, err := ParseSDP(response.Body)
	if err != nil {
		return SDPAnswer{}, fmt.Errorf("parse re-INVITE SDP answer: %w", err)
	}
	if contact := strings.TrimSpace(response.GetHeader("Contact")); contact != "" {
		remoteTarget, err := parseNameAddrTarget(contact)
		if err != nil {
			return SDPAnswer{}, fmt.Errorf("parse re-INVITE Contact: %w", err)
		}
		d.remoteTarget = remoteTarget
	}
	ack := d.buildReinviteACK(response)
	if err := d.client.write(ack); err != nil {
		return SDPAnswer{}, fmt.Errorf("send re-INVITE ACK: %w", err)
	}
	return answer, nil
}

func (d *InboundDialog) buildReinviteRequest(offerSDP string) (*sip.Request, error) {
	contact, err := BuildRegisterContact(d.fromURI, d.client.localAddr)
	if err != nil {
		return nil, fmt.Errorf("build re-INVITE Contact: %w", err)
	}
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.localTag),
		"To":           d.remoteTo,
		"Call-ID":      d.callID,
		"CSeq":         fmt.Sprintf("%d INVITE", d.client.cseq),
		"Contact":      fmt.Sprintf("<%s>", contact),
		"Content-Type": "application/sdp",
		"User-Agent":   d.client.userAgent,
	}
	headerFields := []sip.Header{
		{Name: "Via", Value: headers["Via"]},
		{Name: "Max-Forwards", Value: headers["Max-Forwards"]},
		{Name: "From", Value: headers["From"]},
		{Name: "To", Value: headers["To"]},
		{Name: "Call-ID", Value: headers["Call-ID"]},
		{Name: "CSeq", Value: headers["CSeq"]},
		{Name: "Contact", Value: headers["Contact"]},
		{Name: "Content-Type", Value: headers["Content-Type"]},
		{Name: "User-Agent", Value: headers["User-Agent"]},
	}
	for _, route := range d.routeSet {
		headerFields = append(headerFields, sip.Header{Name: "Route", Value: route})
	}
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	return &sip.Request{
		Method:       "INVITE",
		URI:          d.remoteTarget,
		Headers:      headers,
		HeaderFields: headerFields,
		Body:         offerSDP,
	}, nil
}

func (d *InboundDialog) buildReinviteACK(response *sip.Response) *sip.Request {
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.localTag),
		"To":           response.GetHeader("To"),
		"Call-ID":      d.callID,
		"CSeq":         fmt.Sprintf("%d ACK", d.client.cseq),
		"User-Agent":   d.client.userAgent,
	}
	headerFields := []sip.Header{
		{Name: "Via", Value: headers["Via"]},
		{Name: "Max-Forwards", Value: headers["Max-Forwards"]},
		{Name: "From", Value: headers["From"]},
		{Name: "To", Value: headers["To"]},
		{Name: "Call-ID", Value: headers["Call-ID"]},
		{Name: "CSeq", Value: headers["CSeq"]},
		{Name: "User-Agent", Value: headers["User-Agent"]},
	}
	for _, route := range d.routeSet {
		headerFields = append(headerFields, sip.Header{Name: "Route", Value: route})
	}
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	return &sip.Request{Method: "ACK", URI: d.remoteTarget, Headers: headers, HeaderFields: headerFields}
}

func (d *InboundDialog) buildByeRequest() *sip.Request {
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.localTag),
		"To":           d.remoteTo,
		"Call-ID":      d.callID,
		"CSeq":         fmt.Sprintf("%d BYE", d.client.cseq),
		"User-Agent":   d.client.userAgent,
	}
	headerFields := []sip.Header{
		{Name: "Via", Value: headers["Via"]},
		{Name: "Max-Forwards", Value: headers["Max-Forwards"]},
		{Name: "From", Value: headers["From"]},
		{Name: "To", Value: headers["To"]},
		{Name: "Call-ID", Value: headers["Call-ID"]},
		{Name: "CSeq", Value: headers["CSeq"]},
		{Name: "User-Agent", Value: headers["User-Agent"]},
	}
	for _, route := range d.routeSet {
		headerFields = append(headerFields, sip.Header{Name: "Route", Value: route})
	}
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	return &sip.Request{Method: "BYE", URI: d.remoteTarget, Headers: headers, HeaderFields: headerFields}
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
