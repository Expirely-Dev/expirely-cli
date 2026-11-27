package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"net/http"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/gcp"
	"github.com/expirely-dev/expirely-cli/internal/scan"
)

const defaultGCPTimeout = 30 * time.Second

const gcpUsage = `expirely tls gcp lists the certificates of a Google Cloud project and when they expire.

Usage
  expirely tls gcp [flags]

Examples
  expirely tls gcp --project acme-production
  GOOGLE_CLOUD_PROJECT=acme-production expirely tls gcp --warn-days 21

Google Cloud
      --project ID        project to read (default GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT)

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time allowed to read the project (default 30s)

Output
      --json              print JSON; the default when stdout is not a terminal
      --status LIST       show only these statuses: expired, expiring, error, unknown, ok, all
                          (default all; a declared agent gets expired,expiring,error,unknown)
      --fields LIST       keep only these keys in each JSON result; target is always kept
      --limit N           show at most N results, most urgent first
  -h, --help              show this help

expirely tls gcp signs in with Application Default Credentials, lists the Compute
SSL certificates with their target proxies and the Certificate Manager
certificates in every location, and changes nothing. A region Google cannot
reach is listed in unreadable, and the run exits 3 unless a certificate
it read exits 1.
`

// runGCP lists the certificates of one Google Cloud project and reports
// them the way a scan reports targets.
func runGCP(ctx context.Context, args []string, s Streams) int {
	c := newCommand(s, args, gcpUsage)
	fs := flag.NewFlagSet("expirely tls gcp", flag.ContinueOnError)
	project := fs.String("project", "", "")
	w := windowFlags(fs, defaultGCPTimeout)
	v := viewFlags(fs)
	rest, code, done := c.parse(fs, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		return c.fail(failf(CodeInvalidFlag, "expirely tls gcp takes no targets, got %q", rest[0]))
	}
	if e := w.check(); e != nil {
		return c.fail(e)
	}
	if e := v.resolve(c, fs); e != nil {
		return c.fail(e)
	}
	if *project == "" && c.Getenv != nil {
		*project = cmp.Or(c.Getenv("GOOGLE_CLOUD_PROJECT"), c.Getenv("CLOUDSDK_CORE_PROJECT"))
	}
	if *project == "" {
		return c.fail(failf(CodeGCPNotConfigured, "no Google Cloud project: none in --project, GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT"))
	}

	newGCP := c.NewGCP
	if newGCP == nil {
		newGCP = gcp.NewService
	}
	svc, err := newGCP(ctx)
	if err != nil {
		return c.fail(failf(CodeGCPNotConfigured, "%v", err))
	}

	start := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, w.timeout)
	stop := c.waiting("Reading the certificates of project " + *project)
	listing, err := gcp.List(readCtx, svc, *project)
	stop()
	cancel()
	if ctx.Err() != nil {
		return c.interrupted(ctx.Err())
	}
	if err != nil {
		return c.fail(gcpError(err))
	}
	now := time.Now()
	r := newReport(now, w.warnDays, gcpFindings(listing.Certificates, now, w.warn()), v)
	r.Unreadable = orEmpty(listing.Unreachable)
	return c.report(r, time.Since(start))
}

// gcpFindings turns a project's certificates into findings. A managed
// certificate that was not issued yet has no end date and is unknown;
// gcp.state says why.
func gcpFindings(certs []gcp.Certificate, now time.Time, warn time.Duration) []scan.Finding {
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

// gcpError gives a Google Cloud failure its code: a project with Compute
// Engine or billing disabled is gcp_compute_disabled, refused credentials or
// missing permissions gcp_access_denied, anything else gcp_request_failed.
func gcpError(err error) *Error {
	var apiErr *gcp.APIError
	if errors.As(err, &apiErr) && apiErr.Disabled() {
		return failf(CodeGCPComputeDisabled, "%v", err)
	}
	if errors.As(err, &apiErr) && (apiErr.Code == http.StatusUnauthorized || apiErr.Code == http.StatusForbidden) {
		return failf(CodeGCPAccessDenied, "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failf(CodeGCPRequestFailed, "reading the project timed out: %v", err)
	}
	return failf(CodeGCPRequestFailed, "%v", err)
}
