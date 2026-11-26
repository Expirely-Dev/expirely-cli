package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/target"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expirely test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, pool: pool}
}

func (ca testCA) leaf(t *testing.T, dnsName string, notAfter time.Time) tls.Certificate {
	t.Helper()
	notBefore := time.Now().Add(-time.Hour)
	if notAfter.Before(notBefore) {
		notBefore = notAfter.Add(-time.Hour)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve accepts connections on 127.0.0.1 and runs handle on each until the
// test ends; it returns the listener port.
func serve(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func serveTLS(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return serve(t, func(c net.Conn) {
		conn := tls.Server(c, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.HandshakeContext(ctx)
	})
}

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
	ca := newCA(t)
	now := time.Now()

	tests := []struct {
		name       string
		dnsName    string
		notAfter   time.Time
		roots      *x509.CertPool
		wantVerify bool
	}{
		{name: "valid chain verifies", dnsName: "localhost", notAfter: now.Add(10 * 24 * time.Hour), roots: ca.pool, wantVerify: true},
		{name: "expired leaf is still read", dnsName: "localhost", notAfter: now.Add(-time.Hour), roots: ca.pool},
		{name: "untrusted root is still read", dnsName: "localhost", notAfter: now.Add(10 * 24 * time.Hour), roots: x509.NewCertPool()},
		{name: "name mismatch is still read", dnsName: "other.example", notAfter: now.Add(10 * 24 * time.Hour), roots: ca.pool},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := serveTLS(t, ca.leaf(t, tt.dnsName, tt.notAfter))
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
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	_, err = Prober{}.Probe(testContext(t), localhost(port))

	var pe *Error
	if !errors.As(err, &pe) || pe.Op != "dial" {
		t.Fatalf("Probe() error = %v, want *Error with Op dial", err)
	}
}

func TestProbeHandshakeTimeout(t *testing.T) {
	release := make(chan struct{})
	port := serve(t, func(net.Conn) { <-release })
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
