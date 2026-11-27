package target

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  Target
	}{
		{"example.com", Target{"example.com", 443}},
		{"  Example.COM  ", Target{"example.com", 443}},
		{"example.com.", Target{"example.com", 443}},
		{"example.com:8443", Target{"example.com", 8443}},
		{"https://example.com", Target{"example.com", 443}},
		{"HTTPS://example.com:9443/path?q=1#frag", Target{"example.com", 9443}},
		{"192.0.2.10", Target{"192.0.2.10", 443}},
		{"192.0.2.10:636", Target{"192.0.2.10", 636}},
		{"::1", Target{"::1", 443}},
		{"2001:db8::1", Target{"2001:db8::1", 443}},
		{"[2001:db8::1]:8443", Target{"2001:db8::1", 8443}},
		{"https://[2001:db8::1]:8443/", Target{"2001:db8::1", 8443}},
		{"localhost:1", Target{"localhost", 1}},
		{"localhost:65535", Target{"localhost", 65535}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		input      string
		wantReason string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{"http://example.com", `scheme "http" does not use TLS`},
		{"ftp://example.com", `scheme "ftp" does not use TLS`},
		{"https://user:pass@example.com", "credentials in the URL"},
		{"https://", "empty host"},
		{":443", "empty host"},
		{".", "empty host"},
		{".:443", "empty host"},
		{"example.com:0", `port "0" is not between 1 and 65535`},
		{"example.com:65536", `port "65536" is not between 1 and 65535`},
		{"example.com:https", `port "https" is not between 1 and 65535`},
		{"example.com:443:1", "expected host or host:port"},
		{"exa mple.com", "invalid character"},
		{"[", "invalid character"},
		{"exa..mple.com", "invalid character"},
		{"éxample.com", "invalid character"},
		{"--json", "starts or ends with a hyphen"},
		{"-example.com", "starts or ends with a hyphen"},
		{"example-.com:8443", "starts or ends with a hyphen"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := Parse(tt.input)
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error = %v, want *ParseError", tt.input, err)
			}
			if pe.Input != tt.input {
				t.Errorf("ParseError.Input = %q, want %q", pe.Input, tt.input)
			}
			if !strings.Contains(pe.Reason, tt.wantReason) {
				t.Errorf("ParseError.Reason = %q, want it to contain %q", pe.Reason, tt.wantReason)
			}
		})
	}
}

func TestTargetString(t *testing.T) {
	tests := []struct {
		target Target
		want   string
	}{
		{Target{"example.com", 443}, "example.com:443"},
		{Target{"2001:db8::1", 8443}, "[2001:db8::1]:8443"},
	}
	for _, tt := range tests {
		if got := tt.target.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"example.com", "example.com:8443", "https://example.com/x", "[::1]:443", "::1", "", ":0", "http://x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := Parse(input)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error %T is not *ParseError", input, err)
			}
			return
		}
		if got.Host == "" || got.Port < 1 || got.Port > 65535 {
			t.Fatalf("Parse(%q) = %+v, want non-empty host and port in 1-65535", input, got)
		}
		again, err := Parse(got.String())
		if err != nil || again != got {
			t.Fatalf("Parse(%q).String() = %q does not round-trip: %+v, %v", input, got.String(), again, err)
		}
	})
}
