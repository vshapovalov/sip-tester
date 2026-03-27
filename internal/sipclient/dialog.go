package sipclient

import (
	"context"
	"fmt"
	"time"

	"github.com/emiago/sipgo/sip"
)

type Dialog struct {
	client    *Client
	fromURI   string
	toURI     string
	remoteTo  string
	sdpAnswer SDPAnswer
}

func (d *Dialog) SDPAnswer() SDPAnswer {
	return d.sdpAnswer
}

func (d *Dialog) Bye(ctx context.Context) error {
	d.client.cseq++
	bye := &sip.Request{
		Method: "BYE",
		URI:    d.toURI,
		Headers: map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.client.localTag),
			"To":           d.remoteTo,
			"Call-ID":      d.client.callID,
			"CSeq":         fmt.Sprintf("%d BYE", d.client.cseq),
		},
	}
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
	info := &sip.Request{
		Method: "INFO",
		URI:    d.toURI,
		Headers: map[string]string{
			"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
			"Max-Forwards": "70",
			"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.client.localTag),
			"To":           d.remoteTo,
			"Call-ID":      d.client.callID,
			"CSeq":         fmt.Sprintf("%d INFO", d.client.cseq),
			"Content-Type": payload.ContentType,
		},
		Body: payload.Body,
	}
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
