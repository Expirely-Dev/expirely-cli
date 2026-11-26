package scan

import (
	"time"

	"github.com/bycavii/expirely-cli/internal/acm"
)

// FromACM turns ACM certificates into findings, with the same statuses as a
// scan. A certificate that was never issued, such as one pending
// validation, has no end date and is left out. ACM does not verify the
// chain for a host, so trust fields stay nil.
func FromACM(certs []acm.Certificate, now time.Time, warn time.Duration) []Finding {
	findings := make([]Finding, 0, len(certs))
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		days := daysLeft(c.NotAfter.Sub(now))
		expires := c.NotAfter.UTC()
		inUseBy := c.InUseBy
		if inUseBy == nil {
			inUseBy = []string{}
		}
		findings = append(findings, Finding{
			Target:    c.Domain,
			Status:    expiryStatus(*c.NotAfter, now, warn),
			DaysLeft:  &days,
			ExpiresAt: &expires,
			ACM: &ACMInfo{
				ARN:                c.ARN,
				Type:               c.Type,
				Imported:           c.Imported(),
				Status:             c.Status,
				RenewalEligibility: c.RenewalEligibility,
				InUseBy:            inUseBy,
			},
		})
	}
	return findings
}
