// Package cli implements the expirely command line: it parses arguments,
// writes results to stdout and errors to stderr, and returns the process
// exit code instead of calling os.Exit, so tests drive it through Run.
//
// Output is JSON when --json is set or stdout is not a terminal, and text
// otherwise. Help is always text.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"time"

	"github.com/bycavii/expirely-cli/internal/probe"
	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/target"
)

// Exit codes returned by Run, in order of precedence when a scan has
// several outcomes: ExitFindings when any certificate is expired or
// expiring, then ExitFailure when any target could not be read.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitFailure  = 3
)

// Streams holds the standard streams Run reads from and writes to.
// StdoutIsTerminal selects text output when --json is not set.
type Streams struct {
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	StdoutIsTerminal bool
}

const (
	defaultWarnDays = 30
	defaultTimeout  = 10 * time.Second
)

const usage = `Usage: expirely [flags] TARGET...

Find every TLS certificate you serve and when it expires.

TARGET is host, host:port, [ipv6]:port or an https:// URL; the port
defaults to 443.

Flags:
  -h, --help             show this help
      --json             print JSON; the default when stdout is not a terminal
      --timeout DURATION time allowed per target to connect and handshake (default 10s)
      --version          print the version
      --warn-days N      report certificates expiring within N days (default 30)

Exit codes: 0 all ok, 1 a certificate is expired or expiring,
2 usage error, 3 a target could not be read.
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; errors go to
// stderr and exit with the code errorCodes assigns to them.
func Run(ctx context.Context, args []string, s Streams) int {
	jsonOut := !s.StdoutIsTerminal || wantsJSON(args)

	fs := flag.NewFlagSet("expirely", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	showVersion := fs.Bool("version", false, "")
	fs.Bool("json", false, "")
	warnDays := fs.Int("warn-days", defaultWarnDays, "")
	timeout := fs.Duration("timeout", defaultTimeout, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, usage)
			return ExitOK
		}
		return fail(s, jsonOut, failf(CodeInvalidFlag, "%v", err))
	}

	if *showVersion {
		return printVersion(s, jsonOut)
	}
	if *warnDays < 0 {
		return fail(s, jsonOut, failf(CodeInvalidFlag, "--warn-days must be 0 or more, got %d", *warnDays))
	}
	if *timeout <= 0 {
		return fail(s, jsonOut, failf(CodeInvalidFlag, "--timeout must be positive, got %s", *timeout))
	}
	if fs.NArg() == 0 {
		return fail(s, jsonOut, failf(CodeMissingArguments, "no targets: pass at least one host, host:port or https:// URL"))
	}

	targets := make([]target.Target, 0, fs.NArg())
	for _, arg := range fs.Args() {
		t, err := target.Parse(arg)
		if err != nil {
			return fail(s, jsonOut, failf(CodeInvalidTarget, "%v", err))
		}
		targets = append(targets, t)
	}

	now := time.Now()
	findings := scan.Scan(ctx, probe.Prober{}, targets, scan.Options{
		Warn:    time.Duration(*warnDays) * 24 * time.Hour,
		Timeout: *timeout,
		Now:     now,
	})

	report := newReport(now, *warnDays, findings)
	if jsonOut {
		if code := writeJSON(s, jsonOut, report); code != ExitOK {
			return code
		}
	} else {
		writeText(s.Stdout, report)
	}
	return exitCode(findings)
}

func exitCode(findings []scan.Finding) int {
	code := ExitOK
	for _, f := range findings {
		switch f.Status {
		case scan.StatusExpired, scan.StatusExpiring:
			return ExitFindings
		case scan.StatusError:
			code = ExitFailure
		}
	}
	return code
}

// wantsJSON reports whether args request JSON, read before flag parsing so
// that a parse error is already reported in the format the caller asked for.
func wantsJSON(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		return a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true"
	})
}

func printVersion(s Streams, jsonOut bool) int {
	if jsonOut {
		return writeJSON(s, jsonOut, map[string]string{"version": version()})
	}
	fmt.Fprintf(s.Stdout, "expirely %s\n", version())
	return ExitOK
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}
