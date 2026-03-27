package sip

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type Request struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string
	Body    string
}

type Response struct {
	Version    string
	StatusCode int
	Reason     string
	Headers    map[string]string
	Body       string
}

func ParseMessage(raw []byte) (*Request, *Response, error) {
	s := string(raw)
	parts := strings.SplitN(s, "\r\n\r\n", 2)
	head := parts[0]
	body := ""
	if len(parts) == 2 {
		body = parts[1]
	}

	sc := bufio.NewScanner(strings.NewReader(head))
	if !sc.Scan() {
		return nil, nil, fmt.Errorf("empty SIP message")
	}
	startLine := sc.Text()

	headers := map[string]string{}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	if strings.HasPrefix(startLine, "SIP/") {
		p := strings.SplitN(startLine, " ", 3)
		if len(p) < 3 {
			return nil, nil, fmt.Errorf("bad response line: %q", startLine)
		}
		code, err := strconv.Atoi(p[1])
		if err != nil {
			return nil, nil, fmt.Errorf("bad status code: %w", err)
		}
		return nil, &Response{Version: p[0], StatusCode: code, Reason: p[2], Headers: headers, Body: body}, nil
	}

	p := strings.SplitN(startLine, " ", 3)
	if len(p) != 3 {
		return nil, nil, fmt.Errorf("bad request line: %q", startLine)
	}
	return &Request{Method: p[0], URI: p[1], Version: p[2], Headers: headers, Body: body}, nil, nil
}

func BuildRequest(req *Request) []byte {
	version := req.Version
	if version == "" {
		version = "SIP/2.0"
	}
	buf := bytes.NewBufferString(fmt.Sprintf("%s %s %s\r\n", req.Method, req.URI, version))
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers["Content-Length"] = strconv.Itoa(len(req.Body))
	for k, v := range req.Headers {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	buf.WriteString("\r\n")
	buf.WriteString(req.Body)
	return buf.Bytes()
}

func BuildResponse(resp *Response) []byte {
	version := resp.Version
	if version == "" {
		version = "SIP/2.0"
	}
	buf := bytes.NewBufferString(fmt.Sprintf("%s %d %s\r\n", version, resp.StatusCode, resp.Reason))
	if resp.Headers == nil {
		resp.Headers = map[string]string{}
	}
	resp.Headers["Content-Length"] = strconv.Itoa(len(resp.Body))
	for k, v := range resp.Headers {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	buf.WriteString("\r\n")
	buf.WriteString(resp.Body)
	return buf.Bytes()
}
