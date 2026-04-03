package sip

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Header struct {
	Name  string
	Value string
}

type Request struct {
	Method       string
	URI          string
	Version      string
	Headers      map[string]string
	HeaderFields []Header
	Body         string
}

type Response struct {
	Version      string
	StatusCode   int
	Reason       string
	Headers      map[string]string
	HeaderFields []Header
	Body         string
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
	headerFields := make([]Header, 0, 16)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		headers[name] = value
		headerFields = append(headerFields, Header{Name: name, Value: value})
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
		return nil, &Response{Version: p[0], StatusCode: code, Reason: p[2], Headers: headers, HeaderFields: headerFields, Body: body}, nil
	}

	p := strings.SplitN(startLine, " ", 3)
	if len(p) != 3 {
		return nil, nil, fmt.Errorf("bad request line: %q", startLine)
	}
	return &Request{Method: p[0], URI: p[1], Version: p[2], Headers: headers, HeaderFields: headerFields, Body: body}, nil, nil
}

func BuildRequest(req *Request) []byte {
	version := req.Version
	if version == "" {
		version = "SIP/2.0"
	}
	buf := bytes.NewBufferString(fmt.Sprintf("%s %s %s\r\n", req.Method, req.URI, version))
	writeHeaders(buf, req.Headers, req.HeaderFields, req.Body)
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
	writeHeaders(buf, resp.Headers, resp.HeaderFields, resp.Body)
	buf.WriteString("\r\n")
	buf.WriteString(resp.Body)
	return buf.Bytes()
}

func writeHeaders(buf *bytes.Buffer, headers map[string]string, fields []Header, body string) {
	contentLength := strconv.Itoa(len(body))
	if len(fields) > 0 {
		for _, h := range fields {
			if strings.EqualFold(h.Name, "Content-Length") {
				continue
			}
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", h.Name, h.Value))
		}
		buf.WriteString(fmt.Sprintf("Content-Length: %s\r\n", contentLength))
		return
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Length"] = contentLength
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, headers[k]))
	}
}

func (r *Request) GetHeader(name string) string {
	return getHeader(r.Headers, r.HeaderFields, name)
}

func (r *Request) HeaderValues(name string) []string {
	return headerValues(r.Headers, r.HeaderFields, name)
}

func (resp *Response) GetHeader(name string) string {
	return getHeader(resp.Headers, resp.HeaderFields, name)
}

func (resp *Response) HeaderValues(name string) []string {
	return headerValues(resp.Headers, resp.HeaderFields, name)
}

func getHeader(headers map[string]string, fields []Header, name string) string {
	for _, h := range fields {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func headerValues(headers map[string]string, fields []Header, name string) []string {
	if len(fields) > 0 {
		out := make([]string, 0, 2)
		for _, h := range fields {
			if strings.EqualFold(h.Name, name) {
				out = append(out, h.Value)
			}
		}
		return out
	}
	if v := getHeader(headers, nil, name); v != "" {
		return []string{v}
	}
	return nil
}
