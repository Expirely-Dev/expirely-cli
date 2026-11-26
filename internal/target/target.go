// Package target parses the endpoints expirely scans. A target is a host and
// a TCP port that serves TLS; the port defaults to 443.
package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// DefaultPort is the port used when a target does not name one.
const DefaultPort = 443

// Target is a TLS endpoint. Host is a lowercase DNS name or an IP address
// without brackets; Port is between 1 and 65535.
type Target struct {
	Host string
	Port int
}

// String returns host:port, with brackets around an IPv6 host.
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// ParseError reports an input that is not a valid target.
type ParseError struct {
	Input  string
	Reason string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("invalid target %q: %s", e.Input, e.Reason)
}

// Parse reads one target. It accepts host, host:port, [ipv6]:port, a bare
// IPv6 address and https:// URLs, whose path, query and fragment are
// ignored. Surrounding spaces are trimmed. Any other URL scheme, an empty
// host and a port outside 1-65535 are errors of type *ParseError.
func Parse(input string) (Target, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return Target{}, &ParseError{Input: input, Reason: "empty"}
	}

	if strings.Contains(s, "://") {
		return parseURL(input, s)
	}

	if ip := net.ParseIP(s); ip != nil {
		return Target{Host: ip.String(), Port: DefaultPort}, nil
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(s, ":") {
			return Target{}, &ParseError{Input: input, Reason: "expected host or host:port"}
		}
		host, port = s, ""
	}
	return build(input, host, port)
}

func parseURL(input, s string) (Target, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, &ParseError{Input: input, Reason: "not a URL"}
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return Target{}, &ParseError{Input: input, Reason: fmt.Sprintf("scheme %q does not use TLS; only https:// does", u.Scheme)}
	}
	if u.User != nil {
		return Target{}, &ParseError{Input: input, Reason: "credentials in the URL are not accepted"}
	}
	return build(input, u.Hostname(), u.Port())
}

func build(input, host, port string) (Target, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return Target{}, &ParseError{Input: input, Reason: "empty host"}
	}
	p := DefaultPort
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, &ParseError{Input: input, Reason: fmt.Sprintf("port %q is not between 1 and 65535", port)}
		}
		p = n
	}

	if ip := net.ParseIP(host); ip != nil {
		return Target{Host: ip.String(), Port: p}, nil
	}
	if !validHostname(host) {
		return Target{}, &ParseError{Input: input, Reason: "host contains an invalid character"}
	}
	return Target{Host: strings.ToLower(host), Port: p}, nil
}

// validHostname reports whether host uses only letters, digits, hyphens,
// underscores and dots, with no empty label.
func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}
