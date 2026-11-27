package gcp

import (
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

func TestGCPFindings(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	soon := now.Add(12 * day)
	certs := []Certificate{
		{Name: "api-cert", Domain: "api.example.com", Location: "global", NotAfter: &soon},
		{Name: "pending", Domain: "new.example.com", Location: "global", Managed: true, State: "PROVISIONING"},
	}

	got := Findings(certs, now, 30*day)

	if len(got) != 2 {
		t.Fatalf("len(findings) = %d, want 2; a certificate not issued yet is reported, not left out", len(got))
	}
	if f := got[1]; f.Target != "new.example.com" || f.Status != scan.StatusUnknown || f.DaysLeft != nil || f.ExpiresAt != nil || f.GCP.State == nil || *f.GCP.State != "PROVISIONING" {
		t.Errorf("findings[1] = %+v, gcp = %+v; want an unknown certificate with no end date and state PROVISIONING", f, f.GCP)
	}
	if f := got[0]; f.GCP.State != nil {
		t.Errorf("findings[0].gcp.state = %q, want nil for a self-managed certificate", *f.GCP.State)
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != scan.StatusExpiring || f.GCP.Managed || f.GCP.InUseBy == nil || f.Source != scan.SourceGCP || f.TLS.Trusted != nil {
		t.Errorf("findings[0] = %+v, gcp = %+v; want an expiring self-managed certificate, an empty in_use_by and no trust fields", f, f.GCP)
	}
}
