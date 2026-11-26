package scan

import (
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/acm"
)

func TestFromACM(t *testing.T) {
	day := 24 * time.Hour
	soon := now.Add(12 * day)
	later := now.Add(61 * day)
	certs := []acm.Certificate{
		{ARN: "arn:1", Domain: "api.example.com", Type: "IMPORTED", Status: "ISSUED", NotAfter: &soon, InUseBy: []string{"lb-a", "lb-b"}},
		{ARN: "arn:2", Domain: "*.example.com", Type: "AMAZON_ISSUED", Status: "ISSUED", RenewalEligibility: "ELIGIBLE", NotAfter: &later},
		{ARN: "arn:3", Domain: "pending.example.com", Type: "AMAZON_ISSUED", Status: "PENDING_VALIDATION"},
	}

	got := FromACM(certs, now, 30*day)

	if len(got) != 2 {
		t.Fatalf("len(findings) = %d, want 2; a certificate never issued has no end date", len(got))
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != StatusExpiring || *f.DaysLeft != 12 || !f.ACM.Imported || len(f.ACM.InUseBy) != 2 {
		t.Errorf("findings[0] = %+v, acm = %+v; want an expiring imported certificate used twice", f, f.ACM)
	}
	if f := got[1]; f.Status != StatusOK || f.ACM.Imported || f.ACM.InUseBy == nil {
		t.Errorf("findings[1] = %+v, acm = %+v; want an ok ACM-issued certificate with an empty in_use_by", f, f.ACM)
	}
	if got[0].Trusted != nil || got[0].Leaf != nil || got[0].Error != nil {
		t.Errorf("findings[0] has trust, leaf or error fields; ACM findings have none")
	}
}
