package acm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

// regionConcurrency bounds the regions read at once; each region also
// bounds its own DescribeCertificate calls.
const regionConcurrency = 8

// RegionRead is what ReadRegions found in one region: its certificates, or
// the error that stopped the read.
type RegionRead struct {
	Certificates []Certificate
	Err          error
	done         bool
}

// ReadRegions lists the certificates of each region, regionConcurrency
// regions at a time. A region that fails keeps its error and the others
// go on; the context bounds them all.
func ReadRegions(ctx context.Context, acct Account, regions []string) []RegionRead {
	found := make([]RegionRead, len(regions))
	sem := make(chan struct{}, regionConcurrency)
	var wg sync.WaitGroup
admit:
	for i, region := range regions {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break admit
		}
		wg.Go(func() {
			defer func() { <-sem }()
			certs, err := List(ctx, acct.Client(region))
			if err != nil {
				err = fmt.Errorf("%s: %w", region, err)
			}
			found[i] = RegionRead{Certificates: certs, Err: err, done: true}
		})
	}
	wg.Wait()
	for i := range found {
		if !found[i].done {
			found[i].Err = fmt.Errorf("%s: %w", regions[i], ctx.Err())
		}
	}
	return found
}

// Findings turns the certificates of region into findings. A certificate that was
// never issued, such as one pending validation, has no end date and is
// unknown; acm.status says why. One ACM revoked is revoked unless it already
// expired.
func Findings(certs []Certificate, region string, now time.Time, warn time.Duration) []scan.Finding {
	findings := make([]scan.Finding, 0, len(certs))
	for _, cert := range certs {
		f := scan.Unknown(scan.SourceAWSACM, cert.Domain)
		if cert.NotAfter != nil {
			f = scan.Expiry(scan.SourceAWSACM, cert.Domain, *cert.NotAfter, now, warn)
		}
		if cert.Status == string(types.CertificateStatusRevoked) && f.Status != scan.StatusExpired {
			f.Status = scan.StatusRevoked
		}
		var renewal *string
		if cert.RenewalStatus != "" {
			renewal = &cert.RenewalStatus
		}
		f.ACM = &scan.ACMInfo{
			ARN:                cert.ARN,
			Region:             region,
			Type:               cert.Type,
			Imported:           cert.Imported(),
			Status:             cert.Status,
			RenewalEligibility: cert.RenewalEligibility,
			RenewalStatus:      renewal,
			InUseBy:            orEmpty(cert.InUseBy),
		}
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
