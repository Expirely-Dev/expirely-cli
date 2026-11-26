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
	"strings"
	"time"

	"github.com/bycavii/expirely-cli/internal/probe"
	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
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
// StdoutIsTerminal selects text output when --json is not set, and Style is
// how stdout shows that text; the zero Style is plain. StderrIsTerminal
// allows a progress spinner on stderr while a scan runs. Getenv reads the
// environment for agent detection; nil detects no agent.
type Streams struct {
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	StdoutIsTerminal bool
	StderrIsTerminal bool
	Style            ui.Style
	Getenv           func(string) string
}

const (
	defaultWarnDays    = 30
	defaultTimeout     = 10 * time.Second
	defaultConcurrency = 16
)

const tagline = "expirely tells you when the TLS certificates you serve expire."

// intro is what a person sees when they run expirely with nothing to scan:
// a few ways in rather than every flag.
const intro = tagline + `

  expirely example.com          scan one host
  expirely -f hosts.txt         scan a list, one per line
  expirely --help               every flag
`

const usage = tagline + `

Usage
  expirely [flags] TARGET...
  expirely [flags] -f FILE

Examples
  expirely example.com api.example.com:8443
  expirely -f hosts.txt --warn-days 21
  cat hosts.txt | expirely -f - --json | jq .summary

Targets
  -f, --file PATH         read targets from PATH, one per line; - reads stdin
  A target is host, host:port, [ipv6]:port or https://host/path.
  The port defaults to 443.

Scan
      --warn-days N       flag certificates expiring within N days (default 30)
      --timeout DURATION  time each target has to connect and handshake (default 10s)
      --concurrency N     targets scanned at once (default 16)

Output
      --json              print JSON; the default when stdout is not a terminal
      --details           add every certificate of each chain to the JSON
      --version           print the version
  -h, --help              show this help

Exit codes
  0 all ok, 1 expired or expiring, 2 usage error, 3 a target could not be read

Docs: https://github.com/bycavii/expirely-cli
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; errors go to
// stderr and exit with the code errorCodes assigns to them.
func Run(ctx context.Context, args []string, s Streams) int {
	ag := detectAgent(s.Getenv, s.StdoutIsTerminal)
	if ag.Name != "" {
		s.Style = ui.Style{}
	}
	jsonOut := !s.StdoutIsTerminal || ag.Declared || wantsJSON(args)
	out := func() mode { return mode{json: jsonOut, agent: ag.Name != ""} }

	fs := flag.NewFlagSet("expirely", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	showVersion := fs.Bool("version", false, "")
	jsonFlag := fs.Bool("json", false, "")
	warnDays := fs.Int("warn-days", defaultWarnDays, "")
	timeout := fs.Duration("timeout", defaultTimeout, "")
	concurrency := fs.Int("concurrency", defaultConcurrency, "")
	details := fs.Bool("details", false, "")
	var files fileList
	fs.Var(&files, "file", "")
	fs.Var(&files, "f", "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, usage)
			return ExitOK
		}
		return fail(s, out(), failf(CodeInvalidFlag, "%s", flagError(err)))
	}

	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" {
			jsonOut = *jsonFlag
		}
	})

	if *showVersion {
		return printVersion(s, out())
	}
	if *warnDays < 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--warn-days must be 0 or more, got %d", *warnDays))
	}
	if *timeout <= 0 {
		return fail(s, out(), failf(CodeInvalidFlag, "--timeout must be positive, got %s", *timeout))
	}
	if *concurrency < 1 {
		return fail(s, out(), failf(CodeInvalidFlag, "--concurrency must be 1 or more, got %d", *concurrency))
	}

	targets, e := collectTargets(fs.Args(), files, s.Stdin)
	if e != nil {
		return fail(s, out(), e)
	}
	if len(targets) == 0 {
		if len(files) > 0 {
			return fail(s, out(), failf(CodeMissingArguments, "no targets in %s", strings.Join(fileNames(files), ", ")))
		}
		if !jsonOut && ag.Name == "" {
			fmt.Fprint(s.Stderr, intro)
			return errorCodes[CodeMissingArguments]
		}
		return fail(s, out(), failf(CodeMissingArguments, "no targets: pass a host, host:port or https:// URL, or --file"))
	}

	now := time.Now()
	start := time.Now()
	opts := scan.Options{
		Warn:        time.Duration(*warnDays) * 24 * time.Hour,
		Timeout:     *timeout,
		Now:         now,
		Concurrency: *concurrency,
	}
	var spinner *ui.Spinner
	if s.StderrIsTerminal && ag.Name == "" {
		spinner = ui.StartSpinner(s.Stderr, len(targets))
		opts.Progress = spinner.Done
	}
	findings := scan.Scan(ctx, probe.Prober{}, targets, opts)
	if spinner != nil {
		spinner.Stop()
	}

	report := newReport(now, *warnDays, findings, *details)
	if jsonOut {
		if code := writeJSON(s, out(), report); code != ExitOK {
			return code
		}
	} else {
		writeText(s.Style.Writer(s.Stdout), s.Style, report, time.Since(start))
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

func printVersion(s Streams, m mode) int {
	if m.json {
		return writeJSON(s, m, map[string]string{"version": version()})
	}
	fmt.Fprintf(s.Stdout, "expirely %s\n", version())
	return ExitOK
}

// buildVersion is set by the release build with -ldflags -X; it is empty in
// go build and go install builds, which report the module version instead.
var buildVersion string

func version() string {
	if buildVersion != "" {
		return buildVersion
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// flagError rewrites the flag package's messages in the form people type
// flags: "flag provided but not defined: -nope" becomes "unknown flag
// --nope", and "flag needs an argument: -timeout" becomes "--timeout needs a
// value". Other messages are kept, with their flag names given two dashes.
func flagError(err error) string {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return "unknown flag --" + strings.TrimPrefix(name, "-")
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return "--" + strings.TrimPrefix(name, "-") + " needs a value"
	}
	return strings.Replace(msg, " flag -", " flag --", 1)
}
