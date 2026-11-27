package cli

import (
	"context"
	"errors"
	"flag"
	"slices"
	"time"

	"github.com/aws/smithy-go"
	"github.com/bycavii/expirely-cli/internal/acm"
	"github.com/bycavii/expirely-cli/internal/scan"
)

const defaultAWSTimeout = 30 * time.Second

const awsUsage = `expirely aws lists the certificates in AWS Certificate Manager and when they expire.

Usage
  expirely aws [flags]

Examples
  expirely aws --profile production --region us-east-1
  AWS_PROFILE=production expirely aws --warn-days 21

AWS
      --profile NAME      profile from the shared AWS config (default AWS_PROFILE or the default chain)
      --region REGION     region to read (default AWS_REGION or the profile's region)

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time allowed to read ACM (default 30s)

Output
      --json              print JSON; the default when stdout is not a terminal
      --status LIST       show only these statuses: expired, expiring, error, ok, all
                          (default all; a declared agent gets expired,expiring,error)
      --fields LIST       keep only these keys in each JSON result; target is always kept
      --limit N           show at most N results, most urgent first
  -h, --help              show this help

expirely aws only calls acm:ListCertificates and acm:DescribeCertificate and changes nothing.
`

// accessDenied are the AWS error codes that mean the credentials were
// refused or lack the ACM read permissions.
var accessDenied = []string{
	"AccessDeniedException",
	"UnrecognizedClientException",
	"InvalidClientTokenId",
	"ExpiredToken",
	"ExpiredTokenException",
}

// runAWS lists the ACM certificates of one account and region and reports
// them the way a scan reports targets.
func runAWS(ctx context.Context, args []string, s Streams) int {
	c := newCommand(s, args, awsUsage)
	fs := flag.NewFlagSet("expirely aws", flag.ContinueOnError)
	profile := fs.String("profile", "", "")
	region := fs.String("region", "", "")
	w := windowFlags(fs, defaultAWSTimeout)
	v := viewFlags(fs)
	rest, code, done := c.parse(fs, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		return c.fail(failf(CodeInvalidFlag, "expirely aws takes no targets, got %q", rest[0]))
	}
	if e := w.check(); e != nil {
		return c.fail(e)
	}
	if e := v.resolve(c, fs); e != nil {
		return c.fail(e)
	}

	newACM := c.NewACM
	if newACM == nil {
		newACM = func(ctx context.Context, profile, region string) (acm.API, string, error) {
			return acm.NewClient(ctx, profile, region)
		}
	}
	client, resolved, err := newACM(ctx, *profile, *region)
	if err != nil {
		return c.fail(failf(CodeAWSNotConfigured, "%v", err))
	}
	if resolved == "" {
		return c.fail(failf(CodeAWSNotConfigured, "no AWS region: none in --region, AWS_REGION or the profile"))
	}

	start := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, w.timeout)
	certs, err := acm.List(readCtx, client)
	cancel()
	if ctx.Err() != nil {
		return c.interrupted(ctx.Err())
	}
	if err != nil {
		return c.fail(awsError(err))
	}
	now := time.Now()
	return c.report(newReport(now, w.warnDays, acmFindings(certs, now, w.warn()), v), time.Since(start))
}

// acmFindings turns ACM certificates into findings. A certificate that was
// never issued, such as one pending validation, has no end date and is left
// out.
func acmFindings(certs []acm.Certificate, now time.Time, warn time.Duration) []scan.Finding {
	findings := make([]scan.Finding, 0, len(certs))
	for _, cert := range certs {
		if cert.NotAfter == nil {
			continue
		}
		f := scan.Expiry(cert.Domain, *cert.NotAfter, now, warn)
		f.ACM = &scan.ACMInfo{
			ARN:                cert.ARN,
			Type:               cert.Type,
			Imported:           cert.Imported(),
			Status:             cert.Status,
			RenewalEligibility: cert.RenewalEligibility,
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

// awsError gives an AWS failure its code: refused credentials or missing
// permissions are aws_access_denied, anything else aws_request_failed.
func awsError(err error) *Error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && slices.Contains(accessDenied, apiErr.ErrorCode()) {
		return failf(CodeAWSAccessDenied, "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failf(CodeAWSRequestFailed, "reading ACM timed out: %v", err)
	}
	return failf(CodeAWSRequestFailed, "%v", err)
}
