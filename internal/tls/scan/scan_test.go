package scan

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/probe"
	"github.com/expirely-dev/expirely-cli/internal/tls/target"
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
			if got.TLS.Leaf == nil || got.TLS.Leaf.Subject != "CN=leaf" {
				t.Errorf("Leaf = %+v, want subject CN=leaf", got.TLS.Leaf)
			}
			if len(got.TLS.Chain) != len(tt.chain) {
				t.Errorf("len(Chain) = %d, want %d", len(got.TLS.Chain), len(tt.chain))
			}
			if got.Error != nil {
				t.Errorf("Error = %+v, want nil", got.Error)
			}
		})
	}
}

func TestClassifyTrust(t *testing.T) {
	r := result(cert("leaf", now.Add(90*24*time.Hour)))
	if got := Classify(r, now, 0); got.TLS.Trusted == nil || !*got.TLS.Trusted || got.TLS.VerifyError != nil {
		t.Errorf("verified chain: Trusted = %v, VerifyError = %v, want true and nil", got.TLS.Trusted, got.TLS.VerifyError)
	}

	r.VerifyError = errors.New("x509: certificate signed by unknown authority")
	got := Classify(r, now, 0)
	if got.TLS.Trusted == nil || *got.TLS.Trusted {
		t.Errorf("untrusted chain: Trusted = %v, want false", got.TLS.Trusted)
	}
	if got.TLS.VerifyError == nil || *got.TLS.VerifyError != r.VerifyError.Error() {
		t.Errorf("untrusted chain: VerifyError = %v, want %q", got.TLS.VerifyError, r.VerifyError)
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

	got, err := Scan(context.Background(), p, []target.Target{ok, down, bad}, Options{Warn: 30 * 24 * time.Hour, Timeout: time.Second, Now: now})
	if err != nil {
		t.Fatal(err)
	}

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
		if f.Error != nil && f.Error.Remediation != Remediations[w.code] {
			t.Errorf("findings[%d].Error.Remediation = %q, want the one for %q", i, f.Error.Remediation, w.code)
		}
		if f.DaysLeft != nil || f.TLS.Leaf != nil || f.TLS.Trusted != nil {
			t.Errorf("findings[%d] error finding has certificate fields: %+v", i, f)
		}
	}
}

type slowProber struct {
	inFlight, peak atomic.Int32
}

func (p *slowProber) Probe(ctx context.Context, t target.Target) (probe.Result, error) {
	n := p.inFlight.Add(1)
	defer p.inFlight.Add(-1)
	for {
		old := p.peak.Load()
		if n <= old || p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
		return probe.Result{}, ctx.Err()
	}
	return probe.Result{Target: t, Chain: []*x509.Certificate{cert(t.Host, now.Add(time.Duration(t.Port)*24*time.Hour))}}, nil
}

func TestScanBoundsConcurrencyAndKeepsOrder(t *testing.T) {
	const limit = 4
	var targets []target.Target
	for i := 1; i <= 20; i++ {
		targets = append(targets, target.Target{Host: fmt.Sprintf("h%d.example", i), Port: i})
	}
	p := &slowProber{}

	var progress atomic.Int32
	got, err := Scan(context.Background(), p, targets, Options{Warn: 0, Timeout: time.Second, Now: now, Concurrency: limit, Progress: func() { progress.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}

	if n := int(progress.Load()); n != len(targets) {
		t.Errorf("Progress called %d times, want once per target (%d)", n, len(targets))
	}

	if peak := p.peak.Load(); peak > limit || peak < 2 {
		t.Errorf("peak concurrent probes = %d, want between 2 and %d", peak, limit)
	}
	if p.inFlight.Load() != 0 {
		t.Errorf("probes still in flight after Scan returned: %d", p.inFlight.Load())
	}
	for i, f := range got {
		if f.Target != targets[i].String() {
			t.Errorf("findings[%d].Target = %q, want %q", i, f.Target, targets[i].String())
		}
		if f.DaysLeft == nil || *f.DaysLeft != targets[i].Port {
			t.Errorf("findings[%d].DaysLeft = %v, want %d", i, f.DaysLeft, targets[i].Port)
		}
	}
}

func TestScanConcurrencyBelowOne(t *testing.T) {
	p := &slowProber{}
	targets := []target.Target{{Host: "a.example", Port: 1}, {Host: "b.example", Port: 2}}

	got, err := Scan(context.Background(), p, targets, Options{Timeout: time.Second, Now: now, Concurrency: 0})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || p.peak.Load() != 1 {
		t.Errorf("len(findings) = %d, peak = %d, want 2 findings probed one at a time", len(got), p.peak.Load())
	}
}

type countingProber struct{ calls atomic.Int32 }

func (p *countingProber) Probe(ctx context.Context, t target.Target) (probe.Result, error) {
	p.calls.Add(1)
	<-ctx.Done()
	return probe.Result{}, &probe.Error{Target: t, Op: "dial", Err: ctx.Err()}
}

func TestScanStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &countingProber{}
	targets := make([]target.Target, 50)
	for i := range targets {
		targets[i] = target.Target{Host: "t.example", Port: i + 1}
	}
	cancel()

	got, err := Scan(ctx, p, targets, Options{Timeout: time.Second, Now: now, Concurrency: 2})

	if !errors.Is(err, context.Canceled) || got != nil {
		t.Errorf("Scan() = %d findings, %v; want none and context.Canceled", len(got), err)
	}
	if n := p.calls.Load(); n != 0 {
		t.Errorf("Scan probed %d targets after its context was canceled, want 0", n)
	}
}

func TestExpiry(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name     string
		notAfter time.Time
		want     Status
		wantDays int
	}{
		{name: "ends now", notAfter: now, want: StatusExpired, wantDays: 0},
		{name: "ended a day and an hour ago", notAfter: now.Add(-day - time.Hour), want: StatusExpired, wantDays: -2},
		{name: "inside the window", notAfter: now.Add(12 * day), want: StatusExpiring, wantDays: 12},
		{name: "on the window's edge", notAfter: now.Add(30 * day), want: StatusOK, wantDays: 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Expiry(SourceAWSACM, "api.example.com", tt.notAfter, now, 30*day)

			if got.Target != "api.example.com" || got.Status != tt.want || *got.DaysLeft != tt.wantDays || !got.ExpiresAt.Equal(tt.notAfter) {
				t.Errorf("Expiry() = %s %s %d days %v, want %s %d days", got.Target, got.Status, *got.DaysLeft, got.ExpiresAt, tt.want, tt.wantDays)
			}
			if got.Kind != KindTLSCertificate || got.Source != SourceAWSACM {
				t.Errorf("Expiry() kind = %q, source = %q, want %q and %q", got.Kind, got.Source, KindTLSCertificate, SourceAWSACM)
			}
			if got.TLS.Trusted != nil || got.TLS.Leaf != nil || got.TLS.Chain != nil || got.Error != nil {
				t.Errorf("Expiry() = %+v, want no trust, leaf, chain or error", got)
			}
		})
	}
}
