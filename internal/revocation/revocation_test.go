package revocation

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tlstest"
)

func serveCRL(t *testing.T, body []byte, requests *atomic.Int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/crl"
}

func leafAndIssuer(t *testing.T, ca tlstest.CA, serial int64, url string) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	pair := ca.RevocableLeaf(t, "localhost", serial, url)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf, ca.Cert
}

func TestCheck(t *testing.T) {
	ca := tlstest.NewCA(t)
	other := tlstest.NewCA(t)
	tomorrow := time.Now().Add(24 * time.Hour)
	crl := ca.CRL(t, tomorrow, 7)

	missing := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(missing.Close)
	elsewhere := serveCRL(t, crl, nil)
	redirect := httptest.NewServer(http.RedirectHandler(elsewhere, http.StatusFound))
	t.Cleanup(redirect.Close)

	tests := []struct {
		name       string
		serial     int64
		url        string
		noIssuer   bool
		maxSize    int64
		wantStatus string
		wantReason string
	}{
		{name: "good", serial: 8, url: serveCRL(t, crl, nil), wantStatus: StatusGood},
		{name: "revoked", serial: 7, url: serveCRL(t, crl, nil), wantStatus: StatusRevoked, wantReason: "revoked on 2026-11-01T00:00:00Z"},
		{name: "no CRL URL", serial: 7, url: "ldap://directory.example/crl", wantStatus: StatusUnknown, wantReason: "names no CRL"},
		{name: "no issuer", serial: 7, url: serveCRL(t, crl, nil), noIssuer: true, wantStatus: StatusUnknown, wantReason: "no issuer certificate"},
		{name: "not found", serial: 7, url: missing.URL + "/crl", wantStatus: StatusUnknown, wantReason: "404 Not Found"},
		{name: "signed by another CA", serial: 7, url: serveCRL(t, other.CRL(t, tomorrow, 7), nil), wantStatus: StatusUnknown, wantReason: "not signed by the certificate's issuer"},
		{name: "out of date", serial: 7, url: serveCRL(t, ca.CRL(t, time.Now().Add(-time.Minute), 7), nil), wantStatus: StatusUnknown, wantReason: "out of date since"},
		{name: "over the size cap", serial: 7, url: serveCRL(t, crl, nil), maxSize: 16, wantStatus: StatusUnknown, wantReason: "is over 16 bytes"},
		{name: "not a CRL", serial: 7, url: serveCRL(t, []byte("<html>"), nil), wantStatus: StatusUnknown, wantReason: "parse the CRL"},
		{name: "redirect to another host", serial: 7, url: redirect.URL + "/crl", wantStatus: StatusUnknown, wantReason: "redirect to another host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf, issuer := leafAndIssuer(t, ca, tt.serial, tt.url)
			if tt.noIssuer {
				issuer = nil
			}
			c := &Checker{MaxSize: tt.maxSize}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			got := c.Check(ctx, leaf, issuer)

			if got.Status != tt.wantStatus || !strings.Contains(got.Reason, tt.wantReason) || (tt.wantReason == "" && got.Reason != "") {
				t.Errorf("Check() = %+v, want status %q and a reason containing %q", got, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

func TestCheckFetchesEachCRLOnce(t *testing.T) {
	ca := tlstest.NewCA(t)
	var requests atomic.Int32
	url := serveCRL(t, ca.CRL(t, time.Now().Add(24*time.Hour), 7), &requests)
	c := &Checker{}

	for _, serial := range []int64{7, 8, 9} {
		leaf, issuer := leafAndIssuer(t, ca, serial, url)
		c.Check(context.Background(), leaf, issuer)
	}

	if n := requests.Load(); n != 1 {
		t.Errorf("CRL requests = %d, want 1 for three certificates that name the same CRL", n)
	}
}

func TestCheckStopsAtTheDeadline(t *testing.T) {
	ca := tlstest.NewCA(t)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); slow.Close() })
	leaf, issuer := leafAndIssuer(t, ca, 7, slow.URL+"/crl")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	got := (&Checker{}).Check(ctx, leaf, issuer)

	if got.Status != StatusUnknown || !strings.Contains(got.Reason, "deadline exceeded") {
		t.Errorf("Check() = %+v, want unknown when the deadline passes", got)
	}
}
