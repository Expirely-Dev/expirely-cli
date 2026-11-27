package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp"
	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
)

const defaultGCPTimeout = 30 * time.Second

const gcpUsage = `expirely gcp lists the SSL certificates of a Google Cloud project and when they expire.

Usage
  expirely gcp [flags]

Examples
  expirely gcp --project acme-production
  GOOGLE_CLOUD_PROJECT=acme-production expirely gcp --warn-days 21

Google Cloud
      --project ID        project to read (default GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT)

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time allowed to read the project (default 30s)

Output
      --json              print JSON; the default when stdout is not a terminal
  -h, --help              show this help

expirely gcp signs in with Application Default Credentials, only lists SSL
certificates and target proxies, and changes nothing.
`

// runGCP lists the SSL certificates of one Google Cloud project and reports
// them the way a scan reports targets.
func runGCP(ctx context.Context, args []string, s Streams) int {
	ag := detectAgent(s.Getenv, s.StdoutIsTerminal)
	if ag.Name != "" {
		s.Style = ui.Style{}
	}
	jsonOut := !s.StdoutIsTerminal || ag.Declared || wantsJSON(args)
	out := func() mode { return mode{json: jsonOut, agent: ag.Name != ""} }

	fs := flag.NewFlagSet("expirely gcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "")
	project := fs.String("project", "", "")
	warnDays := fs.Int("warn-days", defaultWarnDays, "")
	timeout := fs.Duration("timeout", defaultGCPTimeout, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, gcpUsage)
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
		return fail(s, out(), failf(CodeInvalidFlag, "expirely gcp takes no targets, got %q", fs.Arg(0)))
	}
	if *warnDays < 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--warn-days must be 0 or more, got %d", *warnDays))
	}
	if *timeout <= 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--timeout must be positive, got %s", *timeout))
	}
	if *project == "" && s.Getenv != nil {
		*project = s.Getenv("GOOGLE_CLOUD_PROJECT")
		if *project == "" {
			*project = s.Getenv("CLOUDSDK_CORE_PROJECT")
		}
	}
	if *project == "" {
		return fail(s, out(), failf(CodeGCPNotConfigured, "no Google Cloud project: none in --project, GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT"))
	}

	newGCP := s.NewGCP
	if newGCP == nil {
		newGCP = gcp.NewService
	}
	svc, err := newGCP(ctx)
	if err != nil {
		return fail(s, out(), failf(CodeGCPNotConfigured, "%v", err))
	}

	start := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, *timeout)
	certs, err := gcp.List(readCtx, svc, *project)
	cancel()
	if err != nil {
		return fail(s, out(), gcpError(err))
	}

	now := time.Now()
	findings := scan.FromGCP(certs, now, time.Duration(*warnDays)*24*time.Hour)
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

// gcpError gives a Google Cloud failure its code: refused credentials or
// missing permissions are gcp_access_denied, anything else
// gcp_request_failed.
func gcpError(err error) *Error {
	var apiErr *gcp.APIError
	if errors.As(err, &apiErr) && (apiErr.Code == http.StatusUnauthorized || apiErr.Code == http.StatusForbidden) {
		return failf(CodeGCPAccessDenied, "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failf(CodeGCPRequestFailed, "reading the project timed out: %v", err)
	}
	return failf(CodeGCPRequestFailed, "%v", err)
}
