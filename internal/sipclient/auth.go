package sipclient

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type DigestChallenge struct {
	Scheme    string
	Realm     string
	Nonce     string
	Opaque    string
	Algorithm string
	QOP       []string
	Stale     bool
	IsProxy   bool
}

type DigestAuthParams struct {
	Username  string
	Password  string
	Method    string
	URI       string
	Challenge DigestChallenge
	CNonce    string
	NC        string
}

func ParseDigestChallenge(headerValue string, isProxy bool) (DigestChallenge, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return DigestChallenge{}, fmt.Errorf("malformed challenge header: empty value")
	}

	scheme, paramsRaw, found := strings.Cut(headerValue, " ")
	if !found {
		return DigestChallenge{}, fmt.Errorf("malformed challenge header: missing params")
	}
	if !strings.EqualFold(strings.TrimSpace(scheme), "Digest") {
		return DigestChallenge{}, fmt.Errorf("unsupported auth scheme %q", strings.TrimSpace(scheme))
	}

	params, err := parseAuthParams(paramsRaw)
	if err != nil {
		return DigestChallenge{}, fmt.Errorf("malformed challenge header: %w", err)
	}

	ch := DigestChallenge{Scheme: "Digest", IsProxy: isProxy}
	ch.Realm = params["realm"]
	ch.Nonce = params["nonce"]
	ch.Opaque = params["opaque"]
	ch.Algorithm = strings.TrimSpace(params["algorithm"])
	if ch.Algorithm != "" && !strings.EqualFold(ch.Algorithm, "MD5") {
		return DigestChallenge{}, fmt.Errorf("unsupported algorithm %q", ch.Algorithm)
	}
	if ch.Algorithm != "" {
		ch.Algorithm = "MD5"
	}
	if ch.Realm == "" {
		return DigestChallenge{}, fmt.Errorf("missing realm")
	}
	if ch.Nonce == "" {
		return DigestChallenge{}, fmt.Errorf("missing nonce")
	}

	if staleRaw, ok := params["stale"]; ok {
		stale, err := strconv.ParseBool(strings.ToLower(staleRaw))
		if err != nil {
			return DigestChallenge{}, fmt.Errorf("malformed stale value %q", staleRaw)
		}
		ch.Stale = stale
	}

	if qopRaw, ok := params["qop"]; ok {
		for _, item := range strings.Split(qopRaw, ",") {
			v := strings.ToLower(strings.TrimSpace(item))
			if v != "" {
				ch.QOP = append(ch.QOP, v)
			}
		}
		if len(ch.QOP) == 0 {
			return DigestChallenge{}, fmt.Errorf("malformed qop value")
		}
	}

	return ch, nil
}

func SelectDigestQOP(ch DigestChallenge) (string, error) {
	if len(ch.QOP) == 0 {
		return "", nil
	}
	for _, item := range ch.QOP {
		if item == "auth" {
			return "auth", nil
		}
	}
	return "", fmt.Errorf("unsupported qop %q", strings.Join(ch.QOP, ","))
}

func BuildDigestAuthorizationValue(params DigestAuthParams) (string, error) {
	if params.Username == "" {
		return "", fmt.Errorf("username is required")
	}
	if params.Password == "" {
		return "", fmt.Errorf("password is required")
	}
	if params.Method == "" {
		return "", fmt.Errorf("method is required")
	}
	if params.URI == "" {
		return "", fmt.Errorf("uri is required")
	}

	ch := params.Challenge
	qop, err := SelectDigestQOP(ch)
	if err != nil {
		return "", err
	}

	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", params.Username, ch.Realm, params.Password))
	ha2 := md5Hex(fmt.Sprintf("%s:%s", params.Method, params.URI))

	responseInput := fmt.Sprintf("%s:%s:%s", ha1, ch.Nonce, ha2)
	if qop != "" {
		if params.CNonce == "" {
			return "", fmt.Errorf("cnonce is required when qop is used")
		}
		if params.NC == "" {
			return "", fmt.Errorf("nc is required when qop is used")
		}
		responseInput = fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, ch.Nonce, params.NC, params.CNonce, qop, ha2)
	}
	response := md5Hex(responseInput)

	headerParts := map[string]string{
		"username": quoteValue(params.Username),
		"realm":    quoteValue(ch.Realm),
		"nonce":    quoteValue(ch.Nonce),
		"uri":      quoteValue(params.URI),
		"response": quoteValue(response),
	}
	if ch.Algorithm != "" {
		headerParts["algorithm"] = ch.Algorithm
	}
	if ch.Opaque != "" {
		headerParts["opaque"] = quoteValue(ch.Opaque)
	}
	if qop != "" {
		headerParts["qop"] = qop
		headerParts["nc"] = params.NC
		headerParts["cnonce"] = quoteValue(params.CNonce)
	}

	keys := make([]string, 0, len(headerParts))
	for k := range headerParts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]string, 0, len(keys))
	for _, k := range keys {
		ordered = append(ordered, fmt.Sprintf("%s=%s", k, headerParts[k]))
	}

	return "Digest " + strings.Join(ordered, ", "), nil
}

func parseAuthParams(raw string) (map[string]string, error) {
	result := map[string]string{}
	for _, piece := range splitCommaAware(raw) {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		key, value, found := strings.Cut(piece, "=")
		if !found {
			return nil, fmt.Errorf("invalid auth param %q", piece)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		result[key] = unquote(value)
	}
	return result, nil
}

func splitCommaAware(s string) []string {
	var parts []string
	var b strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			inQuotes = !inQuotes
			b.WriteByte(ch)
		case ',':
			if inQuotes {
				b.WriteByte(ch)
				continue
			}
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(ch)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, b.String())
	}
	return parts
}

func md5Hex(v string) string {
	h := md5.Sum([]byte(v))
	return hex.EncodeToString(h[:])
}

func quoteValue(v string) string {
	v = strings.ReplaceAll(v, `\\`, `\\\\`)
	v = strings.ReplaceAll(v, `"`, `\\"`)
	return `"` + v + `"`
}

func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = strings.TrimPrefix(v, `"`)
		v = strings.TrimSuffix(v, `"`)
	}
	v = strings.ReplaceAll(v, `\\"`, `"`)
	v = strings.ReplaceAll(v, `\\\\`, `\\`)
	return v
}
