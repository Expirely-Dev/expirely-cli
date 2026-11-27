package gcp

import (
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

// Findings turns a project's certificates into findings. A managed
// certificate that was not issued yet has no end date and is unknown;
// gcp.state says why.
func Findings(certs []Certificate, now time.Time, warn time.Duration) []scan.Finding {
	findings := make([]scan.Finding, 0, len(certs))
	for _, cert := range certs {
		f := scan.Unknown(scan.SourceGCP, cert.Domain)
		if cert.NotAfter != nil {
			f = scan.Expiry(scan.SourceGCP, cert.Domain, *cert.NotAfter, now, warn)
		}
		var state *string
		if cert.State != "" {
			state = &cert.State
		}
		f.GCP = &scan.GCPInfo{Name: cert.Name, Location: cert.Location, Source: cert.Source, Managed: cert.Managed, State: state, InUseBy: orEmpty(cert.InUseBy)}
		findings = append(findings, f)
	}
	return findings
}

// orEmpty returns s, or an empty slice for nil, so JSON prints [] rather
// than null for a certificate nothing uses.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
