package cli

import "testing"

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		hostPort string
		want     string
	}{
		{
			name:     "already sip URI",
			raw:      "sip:alice@example.com",
			hostPort: "pbx.example.com:5060",
			want:     "sip:alice@example.com",
		},
		{
			name:     "user with dns host",
			raw:      "1001",
			hostPort: "pbx.example.com:5060",
			want:     "sip:1001@pbx.example.com",
		},
		{
			name:     "user with ipv6 host",
			raw:      "1001",
			hostPort: "[2001:db8::1]:5060",
			want:     "sip:1001@2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeURI(tt.raw, tt.hostPort)
			if err != nil {
				t.Fatalf("NormalizeURI returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeURI() = %q, want %q", got, tt.want)
			}
		})
	}
}
