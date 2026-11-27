package scan

import (
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp"
)

func TestFromGCP(t *testing.T) {
	soon := now.Add(12 * 24 * time.Hour)
	certs := []gcp.Certificate{
		{Name: "api-cert", Domain: "api.example.com", Location: "global", NotAfter: &soon, InUseBy: []string{"p1", "p2"}},
		{Name: "pending", Domain: "new.example.com", Location: "global", Managed: true},
	}

	got := FromGCP(certs, now, 30*24*time.Hour)

	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1; a certificate not issued yet has no end date", len(got))
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != StatusExpiring || f.GCP.Managed || len(f.GCP.InUseBy) != 2 || f.Trusted != nil {
		t.Errorf("findings[0] = %+v, gcp = %+v; want an expiring self-managed certificate used twice and no trust fields", f, f.GCP)
	}
}
