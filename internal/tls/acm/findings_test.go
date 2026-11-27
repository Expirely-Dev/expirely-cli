package acm

import (
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

func TestACMFindings(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	soon, later := now.Add(12*day), now.Add(61*day)
	certs := []Certificate{
		{ARN: "arn:1", Domain: "api.example.com", Type: "IMPORTED", Status: "ISSUED", NotAfter: &soon, InUseBy: []string{"lb-a", "lb-b"}},
		{ARN: "arn:2", Domain: "*.example.com", Type: "AMAZON_ISSUED", Status: "ISSUED", RenewalEligibility: "ELIGIBLE", NotAfter: &later},
		{ARN: "arn:3", Domain: "pending.example.com", Type: "AMAZON_ISSUED", Status: "PENDING_VALIDATION"},
	}

	got := Findings(certs, "us-east-1", now, 30*day)

	if len(got) != 3 {
		t.Fatalf("len(findings) = %d, want 3; a certificate never issued is reported, not left out", len(got))
	}
	if f := got[2]; f.Target != "pending.example.com" || f.Status != scan.StatusUnknown || f.DaysLeft != nil || f.ExpiresAt != nil || f.ACM == nil || f.ACM.Status != "PENDING_VALIDATION" {
		t.Errorf("findings[2] = %+v, acm = %+v; want an unknown certificate with no end date and its ACM status", f, f.ACM)
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != scan.StatusExpiring || *f.DaysLeft != 12 || !f.ACM.Imported || len(f.ACM.InUseBy) != 2 {
		t.Errorf("findings[0] = %+v, acm = %+v; want an expiring imported certificate used twice", f, f.ACM)
	}
	if f := got[1]; f.Status != scan.StatusOK || f.ACM.Imported || f.ACM.InUseBy == nil {
		t.Errorf("findings[1] = %+v, acm = %+v; want an ok ACM-issued certificate with an empty in_use_by", f, f.ACM)
	}
}

func TestFindingsRevokedByACM(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	later, past := now.Add(90*24*time.Hour), now.Add(-time.Hour)
	certs := []Certificate{
		{ARN: "arn:1", Domain: "revoked.example.com", Status: "REVOKED", NotAfter: &later, RenewalStatus: "FAILED"},
		{ARN: "arn:2", Domain: "gone.example.com", Status: "REVOKED", NotAfter: &past},
	}

	got := Findings(certs, "us-east-1", now, 30*24*time.Hour)

	if got[0].Status != scan.StatusRevoked || got[0].ACM.RenewalStatus == nil || *got[0].ACM.RenewalStatus != "FAILED" {
		t.Errorf("findings[0] = %s, acm = %+v; want revoked with renewal status FAILED", got[0].Status, got[0].ACM)
	}
	if got[1].Status != scan.StatusExpired || got[1].ACM.RenewalStatus != nil {
		t.Errorf("findings[1] = %s, acm = %+v; want expired, which wins over revoked, and no renewal status", got[1].Status, got[1].ACM)
	}
}
