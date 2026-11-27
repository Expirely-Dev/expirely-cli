package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/probe"
	"github.com/expirely-dev/expirely-cli/internal/tls/target"
	"github.com/expirely-dev/expirely-cli/internal/tls/tlstest"
)

func TestReason(t *testing.T) {
	wrap := func(err error) error {
		return &probe.Error{Target: target.Target{Host: "example.com", Port: 443}, Op: "dial", Err: err}
	}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"no certificate", wrap(probe.ErrNoCertificate), "no certificate sent"},
		{"unknown host", wrap(&net.DNSError{Err: "no such host", Name: "nope.example", IsNotFound: true}), "no such host"},
		{"dns failure", wrap(&net.DNSError{Err: "server misbehaving", Name: "x.example"}), "DNS lookup failed"},
		{"refused", wrap(refused), "connection refused"},
		{"reset", wrap(os.NewSyscallError("read", syscall.ECONNRESET)), "connection reset"},
		{"network unreachable", wrap(os.NewSyscallError("connect", syscall.ENETUNREACH)), "network unreachable"},
		{"host unreachable", wrap(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), "host unreachable"},
		{"deadline", wrap(context.DeadlineExceeded), "timed out"},
		{"not tls", wrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), "not a TLS server"},
		{"alert", wrap(tls.AlertError(40)), "rejected by the server: handshake failure"},
		{"eof", wrap(io.EOF), "closed during the handshake"},
		{"other keeps the innermost message", wrap(fmt.Errorf("outer: %w", errors.New("something odd"))), "something odd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reason(tt.err); got != tt.want {
				t.Errorf("reason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTrustIssue(t *testing.T) {
	leaf := cert("leaf", now.Add(90*24*time.Hour))

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"name mismatch", x509.HostnameError{Certificate: leaf, Host: "other.example"}, TrustNameMismatch},
		{"unknown authority", x509.UnknownAuthorityError{Cert: leaf}, TrustUnknownAuthority},
		{"macos system verifier", errors.New("x509: \u201clocalhost\u201d certificate is not trusted"), TrustUnknownAuthority},
		{"expired", x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired}, TrustExpired},
		{"other", x509.CertificateInvalidError{Cert: leaf, Reason: x509.NotAuthorizedToSign}, TrustInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trustIssue(tt.err, leaf); got != tt.want {
				t.Errorf("trustIssue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanExplainsRealHandshakes(t *testing.T) {
	ca := tlstest.NewCA(t)
	far := time.Now().Add(90 * 24 * time.Hour)
	ports := map[string]int{
		"trusted":     tlstest.ServeTLS(t, ca.Leaf(t, "localhost", far)),
		"self-signed": tlstest.ServeTLS(t, tlstest.SelfSigned(t, "localhost", far)),
		"wrong name":  tlstest.ServeTLS(t, ca.Leaf(t, "other.example", far)),
		"expired":     tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(-time.Hour))),
		"plain tcp": tlstest.Serve(t, func(c net.Conn) {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		}),
		"closed": tlstest.ClosedPort(t),
	}

	tests := []struct {
		name       string
		wantIssue  string
		wantReason string
	}{
		{name: "trusted"},
		{name: "self-signed", wantIssue: TrustSelfSigned},
		{name: "wrong name", wantIssue: TrustNameMismatch},
		{name: "expired", wantIssue: TrustExpired},
		{name: "plain tcp", wantReason: "not a TLS server"},
		{name: "closed", wantReason: "connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := target.Target{Host: "localhost", Port: ports[tt.name]}
			findings, err := Scan(context.Background(), probe.Prober{Roots: ca.Pool}, []target.Target{tgt}, Options{Timeout: 2 * time.Second, Now: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			got := findings[0]

			if tt.wantReason != "" {
				if got.Error == nil || got.Error.Reason != tt.wantReason {
					t.Fatalf("Error = %+v, want reason %q", got.Error, tt.wantReason)
				}
				return
			}
			if got.Error != nil {
				t.Fatalf("Error = %+v, want a certificate", got.Error)
			}
			switch {
			case tt.wantIssue == "" && got.TLS.TrustIssue != nil:
				t.Errorf("TrustIssue = %q, want nil for a trusted chain", *got.TLS.TrustIssue)
			case tt.wantIssue != "" && (got.TLS.TrustIssue == nil || *got.TLS.TrustIssue != tt.wantIssue):
				t.Errorf("TrustIssue = %v, want %q", got.TLS.TrustIssue, tt.wantIssue)
			}
		})
	}
}
