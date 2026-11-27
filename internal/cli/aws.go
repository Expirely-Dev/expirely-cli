package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/expirely-dev/expirely-cli/internal/tls/acm"
	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

const defaultAWSTimeout = 30 * time.Second

const awsUsage = `expirely tls aws lists the certificates in AWS Certificate Manager and when
they expire.

Usage
  expirely tls aws [flags]

Examples
  expirely tls aws --profile production --region us-east-1
  expirely tls aws --profile production --region all
  AWS_PROFILE=production expirely tls aws --region us-east-1,eu-west-1

AWS
      --profile NAME      profile from the shared AWS config (default
                          AWS_PROFILE, or the default credential chain)
      --region REGION     a region, a comma list, or all for every enabled
                          region (default AWS_REGION or the profile's region)

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time allowed to read ACM (default 30s)

Output
      --json              print JSON; the default when stdout is not a terminal
` + viewUsage + `  -h, --help              show this help

expirely tls aws only calls acm:ListCertificates and
acm:DescribeCertificate, plus ec2:DescribeRegions for --region all, and
changes nothing. A region it cannot read is listed in unreadable, and the run
exits 3 unless a certificate it read exits 1.
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

// newAWSFlags defines the flags of expirely tls aws.
func newAWSFlags() (fs *flag.FlagSet, profile, region *string, w *window, v *view) {
	fs = flag.NewFlagSet("expirely tls aws", flag.ContinueOnError)
	profile = fs.String("profile", "", "")
	region = fs.String("region", "", "")
	return fs, profile, region, windowFlags(fs, defaultAWSTimeout), viewFlags(fs)
}

// runAWS lists the ACM certificates of one account and region and reports
// them the way a scan reports targets.
func runAWS(ctx context.Context, args []string, s Streams) int {
	c := newCommand(s, args, awsUsage)
	fs, profile, region, w, v := newAWSFlags()
	rest, code, done := c.parse(fs, args)
	if done {
		return code
	}
	if code, done := c.noArguments("expirely tls aws", rest); done {
		return code
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
	found := acm.ReadRegions(readCtx, acct, regions)
	stop()
	if ctx.Err() != nil {
		return c.interrupted(ctx.Err())
	}

	now := time.Now()
	var findings []scan.Finding
	unreadable := []string{}
	var firstErr error
	for i, f := range found {
		if f.Err != nil {
			unreadable = append(unreadable, "acm:"+regions[i])
			firstErr = cmp.Or(firstErr, f.Err)
			continue
		}
		findings = append(findings, acm.Findings(f.Certificates, regions[i], now, w.warn())...)
	}
	if len(unreadable) == len(regions) {
		return c.fail(awsError(firstErr))
	}
	r := newReport(now, w.warnDays, findings, v)
	r.Unreadable = unreadable
	return c.report(r, time.Since(start))
}

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

// orEmpty returns s, or an empty slice for nil, so JSON prints [] rather
// than null for a list with nothing in it.
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
