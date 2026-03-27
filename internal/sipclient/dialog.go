package sipclient

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

type Dialog struct {
	client       *Client
	fromURI      string
	toURI        string
	remoteTo     string
	remoteTag    string
	remoteTarget string
	routeSet     []string
	sdpAnswer    SDPAnswer
}

func (d *Dialog) SDPAnswer() SDPAnswer {
	return d.sdpAnswer
}

func (d *Dialog) Bye(ctx context.Context) error {
	d.client.cseq++
	bye := d.buildInDialogRequest("BYE", "")
	log.Printf("sipclient: BYE destination request-uri=%s routes=%v", bye.URI, d.routeSet)
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

func (d *Dialog) Info(ctx context.Context, payload InfoPayload) error {
	d.client.cseq++
	info := d.buildInDialogRequest("INFO", payload.ContentType)
	info.Body = payload.Body
	if err := d.client.write(info); err != nil {
		return fmt.Errorf("send INFO: %w", err)
	}

	resp, err := d.client.waitForResponse(ctx)
	if err != nil {
		return fmt.Errorf("wait INFO response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("INFO failed with %d %s", resp.StatusCode, resp.Reason)
	}
	return nil
}

func (d *Dialog) HandleIncomingINFO(ctx context.Context) (*InfoPayload, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = d.client.conn.SetReadDeadline(deadline)
	} else {
		_ = d.client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	}

	buf := make([]byte, readBufferSize)
	n, addr, err := d.client.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	req, _, err := sip.ParseMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	if req == nil || req.Method != "INFO" {
		return nil, fmt.Errorf("expected incoming INFO")
	}
	if !d.matchesDialog(req.Headers["Call-ID"], req.Headers["From"], req.Headers["To"]) {
		return nil, fmt.Errorf("incoming INFO did not match dialog")
	}
	log.Printf("sipclient: INFO matched to dialog call-id=%s", req.Headers["Call-ID"])

	payload := &InfoPayload{
		ContentType: req.Headers["Content-Type"],
		Body:        req.Body,
	}

	resp := &sip.Response{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string]string{
			"Via":     req.Headers["Via"],
			"From":    req.Headers["From"],
			"To":      req.Headers["To"],
			"Call-ID": req.Headers["Call-ID"],
			"CSeq":    req.Headers["CSeq"],
		},
	}
	_, err = d.client.conn.WriteToUDP(sip.BuildResponse(resp), addr)
	if err != nil {
		return nil, fmt.Errorf("send 200 for INFO: %w", err)
	}

	return payload, nil
}

func (d *Dialog) buildInDialogRequest(method, contentType string) *sip.Request {
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.client.localTag),
		"To":           d.remoteTo,
		"Call-ID":      d.client.callID,
		"CSeq":         fmt.Sprintf("%d %s", d.client.cseq, method),
	}
	// SIP dialog routing for in-dialog requests:
	// - Request-URI always targets the remote target from 200 OK Contact.
	// - Route headers are populated from the dialog route set (Record-Route from 200 OK).
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	return &sip.Request{
		Method:  method,
		URI:     d.remoteTarget,
		Headers: headers,
	}
}

func (d *Dialog) matchesDialog(callID, fromHeader, toHeader string) bool {
	if callID != d.client.callID {
		return false
	}
	remoteFromTag := extractTag(fromHeader)
	localToTag := extractTag(toHeader)
	return remoteFromTag == d.remoteTag && localToTag == d.client.localTag
}
