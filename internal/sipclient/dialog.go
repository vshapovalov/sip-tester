package sipclient

import (
	"context"
	"fmt"
	"log"
	"strings"

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
	remoteEnded  bool
}

func (d *Dialog) SDPAnswer() SDPAnswer {
	return d.sdpAnswer
}

func (d *Dialog) Bye(ctx context.Context) error {
	if d.remoteEnded {
		return nil
	}
	d.client.cseq++
	bye := d.buildInDialogRequest("BYE", "")
	log.Printf("sipclient: BYE destination request-uri=%s routes=%v", bye.URI, d.routeSet)
	return d.client.sendDialogBYE(ctx, bye, d.matchesRequestDialog)
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

func (d *Dialog) HandleIncomingRequest(ctx context.Context) (string, error) {
	method, err := d.client.handleIncomingDialogRequest(ctx, d.matchesRequestDialog)
	if method == "BYE" {
		d.remoteEnded = true
	}
	return method, err
}

func (d *Dialog) matchesRequestDialog(request *sip.Request) bool {
	return d.matchesDialog(request.GetHeader("Call-ID"), request.GetHeader("From"), request.GetHeader("To"))
}

func (d *Dialog) buildInDialogRequest(method, contentType string) *sip.Request {
	headers := map[string]string{
		"Via":          fmt.Sprintf("SIP/2.0/UDP %s;branch=z9hG4bK-%s;rport", d.client.localAddr.String(), randomToken(9)),
		"Max-Forwards": "70",
		"From":         fmt.Sprintf("<%s>;tag=%s", d.fromURI, d.client.localTag),
		"To":           d.remoteTo,
		"Call-ID":      d.client.callID,
		"CSeq":         fmt.Sprintf("%d %s", d.client.cseq, method),
		"User-Agent":   d.client.userAgent,
	}
	// SIP dialog routing for in-dialog requests:
	// - Request-URI always targets the remote target from 200 OK Contact.
	// - Route headers are populated from the dialog route set (Record-Route from 200 OK).
	headerFields := make([]sip.Header, 0, 10+len(d.routeSet))
	headerFields = append(headerFields,
		sip.Header{Name: "Via", Value: headers["Via"]},
		sip.Header{Name: "Max-Forwards", Value: headers["Max-Forwards"]},
		sip.Header{Name: "From", Value: headers["From"]},
		sip.Header{Name: "To", Value: headers["To"]},
		sip.Header{Name: "Call-ID", Value: headers["Call-ID"]},
		sip.Header{Name: "CSeq", Value: headers["CSeq"]},
		sip.Header{Name: "User-Agent", Value: headers["User-Agent"]},
	)
	for _, route := range d.routeSet {
		headerFields = append(headerFields, sip.Header{Name: "Route", Value: route})
	}
	if len(d.routeSet) > 0 {
		headers["Route"] = strings.Join(d.routeSet, ", ")
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
		headerFields = append(headerFields, sip.Header{Name: "Content-Type", Value: contentType})
	}
	return &sip.Request{
		Method:       method,
		URI:          d.remoteTarget,
		Headers:      headers,
		HeaderFields: headerFields,
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
