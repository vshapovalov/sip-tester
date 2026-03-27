package sipclient

import (
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestParseDigestChallengeWWWAuthenticate(t *testing.T) {
	header := `Digest realm="pbx", nonce="abc123", opaque="xyz", algorithm=MD5, qop="auth,auth-int", stale=false`
	ch, err := ParseDigestChallenge(header, false)
	if err != nil {
		t.Fatalf("ParseDigestChallenge returned error: %v", err)
	}
	if ch.Realm != "pbx" || ch.Nonce != "abc123" || ch.Opaque != "xyz" {
		t.Fatalf("unexpected parsed challenge: %+v", ch)
	}
	if ch.Algorithm != "MD5" {
		t.Fatalf("unexpected algorithm: %q", ch.Algorithm)
	}
	if len(ch.QOP) != 2 || ch.QOP[0] != "auth" || ch.QOP[1] != "auth-int" {
		t.Fatalf("unexpected qop list: %#v", ch.QOP)
	}
	if ch.IsProxy {
		t.Fatal("expected non-proxy challenge")
	}
}

func TestParseDigestChallengeProxyAuthenticate(t *testing.T) {
	header := `Digest realm="proxy", nonce="n-1", qop=auth`
	ch, err := ParseDigestChallenge(header, true)
	if err != nil {
		t.Fatalf("ParseDigestChallenge returned error: %v", err)
	}
	if !ch.IsProxy {
		t.Fatal("expected proxy challenge")
	}
	if ch.Realm != "proxy" || ch.Nonce != "n-1" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
}

func TestSelectDigestQOPModes(t *testing.T) {
	tests := []struct {
		name    string
		qop     []string
		want    string
		wantErr string
	}{
		{name: "absent", qop: nil, want: ""},
		{name: "auth", qop: []string{"auth"}, want: "auth"},
		{name: "auth-and-auth-int", qop: []string{"auth", "auth-int"}, want: "auth"},
		{name: "auth-int-only", qop: []string{"auth-int"}, wantErr: "unsupported qop"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectDigestQOP(DigestChallenge{QOP: tt.qop})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("SelectDigestQOP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildDigestAuthorizationNoQOP(t *testing.T) {
	ch := DigestChallenge{Realm: "testrealm", Nonce: "nonce123"}
	got, err := BuildDigestAuthorizationValue(DigestAuthParams{
		Username:  "Mufasa",
		Password:  "Circle Of Life",
		Method:    "INVITE",
		URI:       "sip:1002@pbx.example.com:5060",
		Challenge: ch,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorizationValue returned error: %v", err)
	}
	if !strings.Contains(got, `response="0b9319b5dd0b90bfb222502c5a3224f6"`) {
		t.Fatalf("unexpected response hash in header: %s", got)
	}
	if strings.Contains(got, "qop=") {
		t.Fatalf("did not expect qop in header: %s", got)
	}
}

func TestBuildDigestAuthorizationWithQOPAuth(t *testing.T) {
	ch := DigestChallenge{Realm: "testrealm", Nonce: "nonce123", Algorithm: "MD5", QOP: []string{"auth"}}
	got, err := BuildDigestAuthorizationValue(DigestAuthParams{
		Username:  "Mufasa",
		Password:  "Circle Of Life",
		Method:    "INVITE",
		URI:       "sip:1002@pbx.example.com:5060",
		Challenge: ch,
		CNonce:    "deadbeefcafebabe",
		NC:        "00000001",
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorizationValue returned error: %v", err)
	}
	if !strings.Contains(got, `qop=auth`) || !strings.Contains(got, `cnonce="deadbeefcafebabe"`) {
		t.Fatalf("missing qop fields in header: %s", got)
	}
	if !strings.Contains(got, `response="e4189d502db9a520a2f3ba886110b0c7"`) {
		t.Fatalf("unexpected response hash in header: %s", got)
	}
}

func TestParseDigestChallengeFromResponse(t *testing.T) {
	resp := &sip.Response{StatusCode: 401, Headers: map[string]string{"WWW-Authenticate": `Digest realm="r", nonce="n"`}}
	ch, headerName, err := parseDigestChallengeFromResponse(resp)
	if err != nil {
		t.Fatalf("parseDigestChallengeFromResponse returned error: %v", err)
	}
	if headerName != "Authorization" {
		t.Fatalf("unexpected auth header: %s", headerName)
	}
	if ch.IsProxy {
		t.Fatal("expected non-proxy challenge")
	}

	resp = &sip.Response{StatusCode: 407, Headers: map[string]string{"Proxy-Authenticate": `Digest realm="r", nonce="n"`}}
	ch, headerName, err = parseDigestChallengeFromResponse(resp)
	if err != nil {
		t.Fatalf("parseDigestChallengeFromResponse returned error: %v", err)
	}
	if headerName != "Proxy-Authorization" {
		t.Fatalf("unexpected auth header: %s", headerName)
	}
	if !ch.IsProxy {
		t.Fatal("expected proxy challenge")
	}
}
