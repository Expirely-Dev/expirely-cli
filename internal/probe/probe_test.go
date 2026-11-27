package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/target"
	"github.com/expirely-dev/expirely-cli/internal/tlstest"
)

func localhost(port int) target.Target {
	return target.Target{Host: "localhost", Port: port}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestProbeReadsChain(t *testing.T) {
	ca := tlstest.NewCA(t)
	now := time.Now()

	tests := []struct {
		name       string
		dnsName    string
		notAfter   time.Time
		roots      *x509.CertPool
		wantVerify bool
	}{
		{name: "valid chain verifies", dnsName: "localhost", notAfter: now.Add(10 * 24 * time.Hour), roots: ca.Pool, wantVerify: true},
		{name: "expired leaf is still read", dnsName: "localhost", notAfter: now.Add(-time.Hour), roots: ca.Pool},
		{name: "untrusted root is still read", dnsName: "localhost", notAfter: now.Add(10 * 24 * time.Hour), roots: x509.NewCertPool()},
		{name: "name mismatch is still read", dnsName: "other.example", notAfter: now.Add(10 * 24 * time.Hour), roots: ca.Pool},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := tlstest.ServeTLS(t, ca.Leaf(t, tt.dnsName, tt.notAfter))
			p := Prober{Roots: tt.roots, Now: func() time.Time { return now }}

			got, err := p.Probe(testContext(t), localhost(port))
			if err != nil {
				t.Fatalf("Probe() error = %v", err)
			}
			if len(got.Chain) != 1 {
				t.Fatalf("len(Chain) = %d, want 1", len(got.Chain))
			}
			if leafName := got.Chain[0].Subject.CommonName; leafName != tt.dnsName {
				t.Errorf("leaf CommonName = %q, want %q", leafName, tt.dnsName)
			}
			if !got.Chain[0].NotAfter.Equal(tt.notAfter.Truncate(time.Second).UTC()) {
				t.Errorf("leaf NotAfter = %v, want %v", got.Chain[0].NotAfter, tt.notAfter.UTC())
			}
			if (got.VerifyError == nil) != tt.wantVerify {
				t.Errorf("VerifyError = %v, want verified = %v", got.VerifyError, tt.wantVerify)
			}
			if got.Target != localhost(port) {
				t.Errorf("Target = %v, want %v", got.Target, localhost(port))
			}
		})
	}
}

func TestProbeDialError(t *testing.T) {
	_, err := Prober{}.Probe(testContext(t), localhost(tlstest.ClosedPort(t)))

	var pe *Error
	if !errors.As(err, &pe) || pe.Op != "dial" {
		t.Fatalf("Probe() error = %v, want *Error with Op dial", err)
	}
}

func TestProbeHandshakeTimeout(t *testing.T) {
	release := make(chan struct{})
	port := tlstest.Serve(t, func(net.Conn) { <-release })
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Prober{}.Probe(ctx, localhost(port))

	var pe *Error
	if !errors.As(err, &pe) || pe.Op != "handshake" {
		t.Fatalf("Probe() error = %v, want *Error with Op handshake", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Probe() took %v, want it bounded by the 200ms context deadline", elapsed)
	}
}

func TestErrorMessage(t *testing.T) {
	e := &Error{Target: target.Target{Host: "example.com", Port: 443}, Op: "dial", Err: errors.New("refused")}
	if got, want := e.Error(), "dial example.com:443: refused"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, e.Err) {
		t.Error("errors.Is(e, e.Err) = false, want true")
	}
}
