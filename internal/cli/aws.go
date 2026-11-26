package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/aws/smithy-go"
	"github.com/bycavii/expirely-cli/internal/acm"
	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
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
	ag := detectAgent(s.Getenv, s.StdoutIsTerminal)
	if ag.Name != "" {
		s.Style = ui.Style{}
	}
	jsonOut := !s.StdoutIsTerminal || ag.Declared || wantsJSON(args)
	out := func() mode { return mode{json: jsonOut, agent: ag.Name != ""} }

	fs := flag.NewFlagSet("expirely aws", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "")
	profile := fs.String("profile", "", "")
	region := fs.String("region", "", "")
	warnDays := fs.Int("warn-days", defaultWarnDays, "")
	timeout := fs.Duration("timeout", defaultAWSTimeout, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, awsUsage)
			return ExitOK
		}
		return fail(s, out(), failf(CodeInvalidFlag, "%s", flagError(err)))
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" {
			jsonOut = *jsonFlag
		}
	})
	if fs.NArg() > 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "expirely aws takes no targets, got %q", fs.Arg(0)))
	}
	if *warnDays < 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--warn-days must be 0 or more, got %d", *warnDays))
	}
	if *timeout <= 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--timeout must be positive, got %s", *timeout))
	}

	newACM := s.NewACM
	if newACM == nil {
		newACM = func(ctx context.Context, profile, region string) (acm.API, string, error) {
			return acm.NewClient(ctx, profile, region)
		}
	}
	client, resolved, err := newACM(ctx, *profile, *region)
	if err != nil {
		return fail(s, out(), failf(CodeAWSNotConfigured, "%v", err))
	}
	if resolved == "" {
		return fail(s, out(), failf(CodeAWSNotConfigured, "no AWS region: none in --region, AWS_REGION or the profile"))
	}

	start := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, *timeout)
	certs, err := acm.List(readCtx, client)
	cancel()
	if err != nil {
		return fail(s, out(), awsError(err))
	}

	now := time.Now()
	findings := scan.FromACM(certs, now, time.Duration(*warnDays)*24*time.Hour)
	report := newReport(now, *warnDays, findings, false)
	if jsonOut {
		if code := writeJSON(s, out(), report); code != ExitOK {
			return code
		}
	} else {
		writeText(s.Style.Writer(s.Stdout), s.Style, report, time.Since(start))
	}
	return exitCode(findings)
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
