// Package probe connects to a TLS endpoint and reads the certificate chain
// it presents. The chain is returned even when it fails verification, since
// expired, untrusted and mismatched certificates are what expirely reports.
// A probe completes the handshake and closes the connection; it sends no
// application data.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bycavii/expirely-cli/internal/target"
)

// Prober reads certificate chains. The zero value verifies against the
// system roots at the current time.
type Prober struct {
	// Roots verifies the chain; nil means the system roots.
	Roots *x509.CertPool
	// Now is the time the chain is verified at; nil means time.Now.
	Now func() time.Time
}

// Result is what a successful handshake revealed.
type Result struct {
	Target target.Target
	// Chain is the certificates the server sent, leaf first. It is never
	// empty in a Result returned without error.
	Chain []*x509.Certificate
	// VerifyError is why the chain does not verify for Target.Host against
	// the roots at the probe time, or nil when it verifies.
	VerifyError error
}

// Error reports a probe that did not reach a certificate chain. Op is
// "dial" or "handshake".
type Error struct {
	Target target.Target
	Op     string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Target, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrNoCertificate is wrapped by an Error when the handshake completes but
// the server sends no certificate.
var ErrNoCertificate = errors.New("server sent no certificate")

// Probe dials t, completes a TLS handshake bounded by ctx and returns the
// chain. Callers bound the probe with a deadline on ctx; without one, the
// operating system's TCP timeouts apply.
func (p Prober) Probe(ctx context.Context, t target.Target) (Result, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", t.String())
	if err != nil {
		return Result{}, &Error{Target: t, Op: "dial", Err: err}
	}
	defer func() { _ = raw.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return Result{}, &Error{Target: t, Op: "dial", Err: err}
		}
	}

	conn := tls.Client(raw, &tls.Config{
		ServerName:         t.Host,
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true, //nolint:gosec // G402: verification happens in verify; expirely must read invalid chains.
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return Result{}, &Error{Target: t, Op: "handshake", Err: err}
	}

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return Result{}, &Error{Target: t, Op: "handshake", Err: ErrNoCertificate}
	}
	return Result{Target: t, Chain: chain, VerifyError: p.verify(t.Host, chain)}, nil
}

func (p Prober) verify(host string, chain []*x509.Certificate) error {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         p.Roots,
		Intermediates: intermediates,
		CurrentTime:   now(),
	})
	return err
}
