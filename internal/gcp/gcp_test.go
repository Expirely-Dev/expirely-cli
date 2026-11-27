package gcp

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp/gcptest"
)

func service(t *testing.T, f gcptest.Fake) *Service {
	t.Helper()
	return &Service{Client: http.DefaultClient, Endpoint: gcptest.Serve(t, "acme-prod", f)}
}

func TestListReadsCertificatesAndTheirProxies(t *testing.T) {
	svc := service(t, gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})

	got, err := List(context.Background(), svc, "acme-prod")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	byName := map[string]Certificate{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if len(got) != 4 {
		t.Fatalf("len(certificates) = %d, want 4 across global and regional scopes", len(got))
	}

	api := byName["api-cert"]
	sort.Strings(api.InUseBy)
	if api.Domain != "api.example.com" || api.Managed || api.Location != "global" || len(api.InUseBy) != 2 ||
		api.InUseBy[0] != "projects/acme-prod/global/targetHttpsProxies/api-https" {
		t.Errorf("api-cert = %+v, want self-managed, global, used by the HTTPS and SSL proxies", api)
	}
	if want := time.Date(2026, 12, 8, 20, 0, 0, 0, time.UTC); api.NotAfter == nil || !api.NotAfter.Equal(want) {
		t.Errorf("api-cert NotAfter = %v, want %v", api.NotAfter, want)
	}
	if www := byName["www-managed"]; www.Domain != "www.example.com" || !www.Managed || len(www.InUseBy) != 0 {
		t.Errorf("www-managed = %+v, want managed, named by its domain, unused", www)
	}
	if internal := byName["internal"]; internal.Location != "us-central1" || len(internal.InUseBy) != 1 {
		t.Errorf("internal = %+v, want regional in us-central1, used by its regional proxy", internal)
	}
	if pending := byName["pending"]; pending.NotAfter != nil {
		t.Errorf("pending = %+v, want no end date before it is issued", pending)
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
