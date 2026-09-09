package sipclient

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/emiago/sipgo/sip"
)

// ErrIgnoredDialogMessage identifies traffic that does not require handling in this dialog.
var ErrIgnoredDialogMessage = errors.New("unrelated or unsupported dialog message")

// ErrRemoteHangup ends an outstanding re-INVITE when the peer terminates the dialog.
var ErrRemoteHangup = errors.New("dialog terminated by remote BYE")

func (c *Client) readDialogMessage(ctx context.Context) (*sip.Request, *sip.Response, *net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(5 * time.Second)
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return nil, nil, nil, fmt.Errorf("set dialog read deadline: %w", err)
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = c.conn.SetReadDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		// Finish the callback before another transaction sets its socket deadline.
		if !stopInterrupt() {
			<-interrupted
		}
	}()
	packet := make([]byte, readBufferSize)
	length, sender, err := c.conn.ReadFromUDP(packet)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, err
	}
	request, response, err := sip.ParseMessage(packet[:length])
	if err != nil {
		return nil, nil, nil, ErrIgnoredDialogMessage
	}
	return request, response, sender, nil
}

func (c *Client) handleIncomingDialogRequest(ctx context.Context, matches func(*sip.Request) bool) (string, error) {
	request, _, sender, err := c.readDialogMessage(ctx)
	if err != nil {
		return "", err
	}
	return c.respondToDialogRequest(request, sender, matches)
}

func (c *Client) respondToDialogRequest(request *sip.Request, sender *net.UDPAddr, matches func(*sip.Request) bool) (string, error) {
	if request == nil || !matches(request) {
		return "", ErrIgnoredDialogMessage
	}
	if request.Method != "INFO" && request.Method != "BYE" {
		return "", ErrIgnoredDialogMessage
	}
	if err := c.respondOKToRequest(request, sender); err != nil {
		return "", err
	}
	return request.Method, nil
}

func (c *Client) respondOKToRequest(request *sip.Request, sender *net.UDPAddr) error {
	headerFields := make([]sip.Header, 0, 8)
	for _, via := range request.HeaderValues("Via") {
		headerFields = append(headerFields, sip.Header{Name: "Via", Value: via})
	}
	for _, name := range []string{"From", "To", "Call-ID", "CSeq"} {
		headerFields = append(headerFields, sip.Header{Name: name, Value: request.GetHeader(name)})
	}
	headerFields = append(headerFields, sip.Header{Name: "User-Agent", Value: c.userAgent})
	response := &sip.Response{StatusCode: 200, Reason: "OK", HeaderFields: headerFields}
	if _, err := c.conn.WriteToUDP(sip.BuildResponse(response), sender); err != nil {
		return fmt.Errorf("respond to %s: %w", request.Method, err)
	}
	log.Printf("sipclient: handled %s call-id=%s", request.Method, request.GetHeader("Call-ID"))
	return nil
}

func (c *Client) sendDialogBYE(ctx context.Context, bye *sip.Request, matches func(*sip.Request) bool) error {
	if err := c.write(bye); err != nil {
		return fmt.Errorf("send BYE: %w", err)
	}
	for {
		request, response, sender, err := c.readDialogMessage(ctx)
		if errors.Is(err, ErrIgnoredDialogMessage) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait BYE response: %w", err)
		}
		if request != nil {
			// Both endpoints can hang up before receiving the other endpoint's BYE.
			if _, err := c.respondToDialogRequest(request, sender, matches); err != nil && !errors.Is(err, ErrIgnoredDialogMessage) {
				return err
			}
			continue
		}
		if !matchesDialogResponse(response, bye) || response.StatusCode < 200 {
			continue
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("BYE failed with %d %s", response.StatusCode, response.Reason)
		}
		return nil
	}
}

func matchesDialogResponse(response *sip.Response, request *sip.Request) bool {
	return response != nil && response.GetHeader("Call-ID") == request.GetHeader("Call-ID") && response.GetHeader("CSeq") == request.GetHeader("CSeq")
}
