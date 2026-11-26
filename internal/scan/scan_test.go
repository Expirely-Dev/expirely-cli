package scan

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/probe"
	"github.com/bycavii/expirely-cli/internal/target"
)

var now = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func cert(name string, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{CommonName: name},
		Issuer:       pkix.Name{CommonName: "issuer"},
		SerialNumber: big.NewInt(255),
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{name},
	}
}

func result(chain ...*x509.Certificate) probe.Result {
	return probe.Result{Target: target.Target{Host: "example.com", Port: 443}, Chain: chain}
}

func TestClassify(t *testing.T) {
	warn := 30 * 24 * time.Hour
	day := 24 * time.Hour

	tests := []struct {
		name       string
		chain      []*x509.Certificate
		wantStatus Status
		wantDays   int
		wantExpiry time.Time
	}{
		{"far from expiry", []*x509.Certificate{cert("leaf", now.Add(90*day))}, StatusOK, 90, now.Add(90 * day)},
		{"exactly at the warning window", []*x509.Certificate{cert("leaf", now.Add(warn))}, StatusOK, 30, now.Add(warn)},
		{"inside the warning window", []*x509.Certificate{cert("leaf", now.Add(warn-time.Second))}, StatusExpiring, 29, now.Add(warn - time.Second)},
		{"expires this instant", []*x509.Certificate{cert("leaf", now)}, StatusExpired, 0, now},
		{"expired an hour ago", []*x509.Certificate{cert("leaf", now.Add(-time.Hour))}, StatusExpired, -1, now.Add(-time.Hour)},
		{"expired ten days ago", []*x509.Certificate{cert("leaf", now.Add(-10*day))}, StatusExpired, -10, now.Add(-10 * day)},
		{
			"intermediate expires before the leaf",
			[]*x509.Certificate{cert("leaf", now.Add(90*day)), cert("intermediate", now.Add(5*day))},
			StatusExpiring, 5, now.Add(5 * day),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(result(tt.chain...), now, warn)

			if got.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.DaysLeft == nil || *got.DaysLeft != tt.wantDays {
				t.Errorf("DaysLeft = %v, want %d", got.DaysLeft, tt.wantDays)
			}
			if got.ExpiresAt == nil || !got.ExpiresAt.Equal(tt.wantExpiry) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, tt.wantExpiry)
			}
			if got.Leaf == nil || got.Leaf.Subject != "CN=leaf" {
				t.Errorf("Leaf = %+v, want subject CN=leaf", got.Leaf)
			}
			if len(got.Chain) != len(tt.chain) {
				t.Errorf("len(Chain) = %d, want %d", len(got.Chain), len(tt.chain))
			}
			if got.Error != nil {
				t.Errorf("Error = %+v, want nil", got.Error)
			}
		})
	}
}

func TestClassifyTrust(t *testing.T) {
	r := result(cert("leaf", now.Add(90*24*time.Hour)))
	if got := Classify(r, now, 0); got.Trusted == nil || !*got.Trusted || got.VerifyError != nil {
		t.Errorf("verified chain: Trusted = %v, VerifyError = %v, want true and nil", got.Trusted, got.VerifyError)
	}

	r.VerifyError = errors.New("x509: certificate signed by unknown authority")
	got := Classify(r, now, 0)
	if got.Trusted == nil || *got.Trusted {
		t.Errorf("untrusted chain: Trusted = %v, want false", got.Trusted)
	}
	if got.VerifyError == nil || *got.VerifyError != r.VerifyError.Error() {
		t.Errorf("untrusted chain: VerifyError = %v, want %q", got.VerifyError, r.VerifyError)
	}
	if got.Status != StatusOK {
		t.Errorf("untrusted chain: Status = %q, want %q; trust does not change the expiry status", got.Status, StatusOK)
	}
}

type fakeProber map[string]func() (probe.Result, error)

func (f fakeProber) Probe(ctx context.Context, t target.Target) (probe.Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		return probe.Result{}, errors.New("probe called without a deadline")
	}
	return f[t.Host]()
}

func TestScan(t *testing.T) {
	ok := target.Target{Host: "ok.example", Port: 443}
	down := target.Target{Host: "down.example", Port: 443}
	bad := target.Target{Host: "bad.example", Port: 8443}
	p := fakeProber{
		"ok.example": func() (probe.Result, error) {
			return probe.Result{Target: ok, Chain: []*x509.Certificate{cert("ok.example", now.Add(60*24*time.Hour))}}, nil
		},
		"down.example": func() (probe.Result, error) {
			return probe.Result{}, &probe.Error{Target: down, Op: "dial", Err: errors.New("connection refused")}
		},
		"bad.example": func() (probe.Result, error) {
			return probe.Result{}, &probe.Error{Target: bad, Op: "handshake", Err: errors.New("tls: bad record")}
		},
	}

	got := Scan(context.Background(), p, []target.Target{ok, down, bad}, Options{Warn: 30 * 24 * time.Hour, Timeout: time.Second, Now: now})

	want := []struct {
		target, code string
		status       Status
	}{
		{"ok.example:443", "", StatusOK},
		{"down.example:443", CodeDialFailed, StatusError},
		{"bad.example:8443", CodeHandshakeFailed, StatusError},
	}
	if len(got) != len(want) {
		t.Fatalf("len(findings) = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		f := got[i]
		if f.Target != w.target || f.Status != w.status {
			t.Errorf("findings[%d] = %s %s, want %s %s", i, f.Target, f.Status, w.target, w.status)
		}
		if w.code == "" {
			continue
		}
		if f.Error == nil || f.Error.Code != w.code {
			t.Errorf("findings[%d].Error = %+v, want code %q", i, f.Error, w.code)
		}
		if f.DaysLeft != nil || f.Leaf != nil || f.Trusted != nil {
			t.Errorf("findings[%d] error finding has certificate fields: %+v", i, f)
		}
	}
}
