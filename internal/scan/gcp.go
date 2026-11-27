package scan

import (
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp"
)

// FromGCP turns a project's SSL certificates into findings, with the same
// statuses as a scan. A managed certificate that was not issued yet has no
// end date and is left out. Google does not verify the chain for a host,
// so trust fields stay nil.
func FromGCP(certs []gcp.Certificate, now time.Time, warn time.Duration) []Finding {
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
			GCP:       &GCPInfo{Name: c.Name, Location: c.Location, Managed: c.Managed, InUseBy: inUseBy},
		})
	}
	return findings
}
