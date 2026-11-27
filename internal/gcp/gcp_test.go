package gcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp/gcptest"
)

func service(t *testing.T, f gcptest.Fake) *Service {
	t.Helper()
	e := gcptest.Serve(t, "acme-prod", f)
	return &Service{Client: http.DefaultClient, ComputeEndpoint: e.Compute, CertificateManagerEndpoint: e.CertificateManager}
}

func byName(certs []Certificate) map[string]Certificate {
	m := map[string]Certificate{}
	for _, c := range certs {
		m[c.Name] = c
	}
	return m
}

func TestListReadsComputeCertificatesAndTheirProxies(t *testing.T) {
	svc := service(t, gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})

	got, err := List(context.Background(), svc, "acme-prod")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(got) != 6 {
		t.Fatalf("len(certificates) = %d, want 4 from Compute and 2 from Certificate Manager", len(got))
	}
	certs := byName(got)
	api := certs["api-cert"]
	sort.Strings(api.InUseBy)
	if api.Domain != "api.example.com" || api.Managed || api.Location != "global" || api.Source != SourceCompute || len(api.InUseBy) != 2 ||
		api.InUseBy[0] != "projects/acme-prod/global/targetHttpsProxies/api-https" {
		t.Errorf("api-cert = %+v, want self-managed, global, from Compute, used by the HTTPS and SSL proxies", api)
	}
	if want := time.Date(2026, 12, 8, 20, 0, 0, 0, time.UTC); api.NotAfter == nil || !api.NotAfter.Equal(want) {
		t.Errorf("api-cert NotAfter = %v, want %v", api.NotAfter, want)
	}
	if www := certs["www-managed"]; www.Domain != "www.example.com" || !www.Managed || len(www.InUseBy) != 0 {
		t.Errorf("www-managed = %+v, want managed, named by its domain, unused", www)
	}
	if internal := certs["internal"]; internal.Location != "us-central1" || len(internal.InUseBy) != 1 {
		t.Errorf("internal = %+v, want regional in us-central1, used by its regional proxy", internal)
	}
	if pending := certs["pending"]; pending.NotAfter != nil {
		t.Errorf("pending = %+v, want no end date before it is issued", pending)
	}
}

func TestListReadsCertificateManagerInEveryLocation(t *testing.T) {
	svc := service(t, gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})

	got, err := List(context.Background(), svc, "acme-prod")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	certs := byName(got)
	shop := certs["shop-cm"]
	if shop.Source != SourceCertificateManager || shop.Domain != "shop.example.com" || !shop.Managed || shop.Location != "global" ||
		len(shop.InUseBy) != 1 || shop.InUseBy[0] != "projects/acme-prod/locations/global/certificateMaps/main/certificateMapEntries/shop" {
		t.Errorf("shop-cm = %+v, want a managed global Certificate Manager certificate used by one map entry", shop)
	}
	legacy := certs["legacy-cm"]
	if legacy.Source != SourceCertificateManager || legacy.Managed || legacy.Location != "us-east1" || len(legacy.InUseBy) != 0 || legacy.NotAfter == nil {
		t.Errorf("legacy-cm = %+v, want a self-managed regional certificate nothing uses", legacy)
	}
}

func TestListWithCertificateManagerDisabled(t *testing.T) {
	bodies := gcptest.Sample("acme-prod")
	bodies["locations"] = gcptest.Error{Status: http.StatusForbidden, Reason: "SERVICE_DISABLED"}
	svc := service(t, gcptest.Fake{Bodies: bodies})

	got, err := List(context.Background(), svc, "acme-prod")

	if err != nil || len(got) != 4 {
		t.Fatalf("List() = %d certificates, %v; want the 4 Compute ones and no error", len(got), err)
	}
}

func TestListReturnsCertificateManagerErrors(t *testing.T) {
	bodies := gcptest.Sample("acme-prod")
	bodies["locations/us-east1/certificates"] = gcptest.Error{Status: http.StatusForbidden, Reason: "IAM_PERMISSION_DENIED"}
	svc := service(t, gcptest.Fake{Bodies: bodies})

	_, err := List(context.Background(), svc, "acme-prod")

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden || !strings.Contains(err.Error(), "us-east1") {
		t.Fatalf("List() error = %v, want the 403 naming the location", err)
	}
}

func TestListFollowsPageTokens(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("pageToken") == "p2" {
			_, _ = w.Write([]byte(`{"items":[{"selfLink":"b"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"selfLink":"a"}],"nextPageToken":"p2"}`))
	}))
	t.Cleanup(srv.Close)

	var links []string
	err := list(context.Background(), srv.Client(), srv.URL+"/projects/x/global/targetSslProxies", func(p struct {
		paged
		Items []proxy `json:"items"`
	}) error {
		for _, item := range p.Items {
			links = append(links, item.SelfLink)
		}
		return nil
	})

	if err != nil || strings.Join(links, ",") != "a,b" || calls.Load() != 2 {
		t.Errorf("list() = %v with items %v after %d calls, want a,b from 2 pages", err, links, calls.Load())
	}
}

func TestListReturnsAPIErrors(t *testing.T) {
	tests := []struct {
		reason       string
		wantDisabled bool
	}{
		{reason: "", wantDisabled: false},
		{reason: "IAM_PERMISSION_DENIED", wantDisabled: false},
		{reason: "SERVICE_DISABLED", wantDisabled: true},
		{reason: "BILLING_DISABLED", wantDisabled: true},
	}
	for _, tt := range tests {
		t.Run("reason "+tt.reason, func(t *testing.T) {
			svc := service(t, gcptest.Fake{Status: http.StatusForbidden, Reason: tt.reason})

			_, err := List(context.Background(), svc, "acme-prod")

			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden || apiErr.Message != "refused by the fake" {
				t.Fatalf("List() error = %v, want a 403 APIError with the server's message", err)
			}
			if apiErr.Reason != tt.reason || apiErr.Disabled() != tt.wantDisabled {
				t.Errorf("Reason = %q, Disabled() = %v; want %q, %v", apiErr.Reason, apiErr.Disabled(), tt.reason, tt.wantDisabled)
			}
		})
	}
}
