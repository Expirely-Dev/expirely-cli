package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go"
	"github.com/expirely-dev/expirely-cli/internal/acm"
	"github.com/expirely-dev/expirely-cli/internal/scan"
)

const defaultAWSTimeout = 30 * time.Second

const awsUsage = `expirely tls aws lists the certificates in AWS Certificate Manager and when they expire.

Usage
  expirely tls aws [flags]

Examples
  expirely tls aws --profile production --region us-east-1
  expirely tls aws --profile production --region all
  AWS_PROFILE=production expirely tls aws --region us-east-1,eu-west-1 --warn-days 21

AWS
      --profile NAME      profile from the shared AWS config (default AWS_PROFILE or the default chain)
      --region REGION     region to read, a comma list, or all for every enabled region
                          (default AWS_REGION or the profile's region)

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time allowed to read ACM (default 30s)

Output
      --json              print JSON; the default when stdout is not a terminal
      --status LIST       show only these statuses: expired, expiring, error, unknown, ok, all
                          (default all; a declared agent gets expired,expiring,error,unknown)
      --fields LIST       keep only these keys in each JSON result; target is always kept
      --limit N           show at most N results, most urgent first
  -h, --help              show this help

expirely tls aws only calls acm:ListCertificates and acm:DescribeCertificate, plus
ec2:DescribeRegions for --region all, and changes nothing. A region it cannot
read is listed in unreadable, and the run exits 3 unless a certificate it read
exits 1.
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
	fs := flag.NewFlagSet("expirely tls aws", flag.ContinueOnError)
	profile := fs.String("profile", "", "")
	region := fs.String("region", "", "")
	w := windowFlags(fs, defaultAWSTimeout)
	v := viewFlags(fs)
	rest, code, done := c.parse(fs, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		return c.fail(failf(CodeInvalidFlag, "expirely tls aws takes no targets, got %q", rest[0]))
	}
	if e := w.check(); e != nil {
		return c.fail(e)
	}
	if e := v.resolve(c, fs); e != nil {
		return c.fail(e)
	}

	regions, explicit, e := regionList(*region)
	if e != nil {
		return c.fail(e)
	}

	newACM := c.NewACM
	if newACM == nil {
		newACM = func(ctx context.Context, profile, region string) (acm.Account, error) {
			return acm.NewSession(ctx, profile, region)
		}
	}
	single := ""
	if len(regions) == 1 {
		single = regions[0]
	}
	acct, err := newACM(ctx, *profile, single)
	if err != nil {
		return c.fail(failf(CodeAWSNotConfigured, "%v", err))
	}

	start := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	switch {
	case !explicit:
		if r := acct.Region(); r != "" {
			regions = []string{r}
		} else {
			return c.fail(failf(CodeAWSNotConfigured, "no AWS region: none in --region, AWS_REGION or the profile"))
		}
	case regions == nil:
		stop := c.waiting("Listing the enabled AWS regions")
		regions, err = acct.EnabledRegions(readCtx)
		stop()
		if ctx.Err() != nil {
			return c.interrupted(ctx.Err())
		}
		if err != nil {
			return c.fail(awsError(err))
		}
		if len(regions) == 0 {
			return c.fail(failf(CodeAWSRequestFailed, "ec2:DescribeRegions returned no enabled region"))
		}
	}

	label := "Reading ACM in " + regions[0]
	if len(regions) > 1 {
		label = "Reading ACM in " + strconv.Itoa(len(regions)) + " regions"
	}
	stop := c.waiting(label)
	found := readRegions(readCtx, acct, regions)
	stop()
	if ctx.Err() != nil {
		return c.interrupted(ctx.Err())
	}

	now := time.Now()
	var findings []scan.Finding
	unreadable := []string{}
	var firstErr error
	for i, f := range found {
		if f.err != nil {
			unreadable = append(unreadable, "acm:"+regions[i])
			firstErr = cmp.Or(firstErr, f.err)
			continue
		}
		findings = append(findings, acmFindings(f.certs, regions[i], now, w.warn())...)
	}
	if len(unreadable) == len(regions) {
		return c.fail(awsError(firstErr))
	}
	r := newReport(now, w.warnDays, findings, v)
	r.Unreadable = unreadable
	return c.report(r, time.Since(start))
}

// regionConcurrency bounds the regions read at once; each region also
// bounds its own DescribeCertificate calls.
const regionConcurrency = 8

// regionPattern matches an AWS region name such as us-east-1 or
// us-gov-west-1.
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// regionList reads --region: empty means the configured region, so
// explicit is false; "all" means every enabled region, returned as nil;
// otherwise one region or a comma list, each checked and kept once in the
// order given.
func regionList(flagValue string) (regions []string, explicit bool, e *Error) {
	if flagValue == "" {
		return nil, false, nil
	}
	if flagValue == "all" {
		return nil, true, nil
	}
	for name := range strings.SplitSeq(flagValue, ",") {
		name = strings.TrimSpace(name)
		if !regionPattern.MatchString(name) {
			return nil, true, failf(CodeInvalidFlag, "--region %q is not an AWS region such as us-east-1; pass one, a comma list, or all", name)
		}
		if !slices.Contains(regions, name) {
			regions = append(regions, name)
		}
	}
	return regions, true, nil
}

type regionRead struct {
	certs []acm.Certificate
	err   error
	done  bool
}

// readRegions lists the certificates of each region, regionConcurrency
// regions at a time. A region that fails keeps its error and the others
// go on; the context bounds them all.
func readRegions(ctx context.Context, acct acm.Account, regions []string) []regionRead {
	found := make([]regionRead, len(regions))
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
			certs, err := acm.List(ctx, acct.Client(region))
			if err != nil {
				err = fmt.Errorf("%s: %w", region, err)
			}
			found[i] = regionRead{certs: certs, err: err, done: true}
		})
	}
	wg.Wait()
	for i := range found {
		if !found[i].done {
			found[i].err = fmt.Errorf("%s: %w", regions[i], ctx.Err())
		}
	}
	return found
}

// acmFindings turns ACM certificates into findings. A certificate that was
// never issued, such as one pending validation, has no end date and is left
// out.
func acmFindings(certs []acm.Certificate, region string, now time.Time, warn time.Duration) []scan.Finding {
	findings := make([]scan.Finding, 0, len(certs))
	for _, cert := range certs {
		if cert.NotAfter == nil {
			continue
		}
		f := scan.Expiry(scan.SourceAWSACM, cert.Domain, *cert.NotAfter, now, warn)
		f.ACM = &scan.ACMInfo{
			ARN:                cert.ARN,
			Region:             region,
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
