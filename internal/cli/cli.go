// Package cli implements the expirely command line: it parses arguments,
// writes results to stdout and errors to stderr, and returns the process
// exit code instead of calling os.Exit, so tests drive it through Run.
//
// Output is JSON when --json is set or stdout is not a terminal, and text
// otherwise. Help is always text.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bycavii/expirely-cli/internal/acm"
	"github.com/bycavii/expirely-cli/internal/gcp"
	"github.com/bycavii/expirely-cli/internal/probe"
	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
)

// Exit codes returned by Run, in order of precedence when a scan has
// several outcomes: ExitFindings when any certificate is expired or
// expiring, then ExitFailure when any target could not be read or a cloud
// command could not read every region.
// ExitInterrupted, 128 plus SIGINT as shells report it, means the run was
// stopped before it ended and printed no results.
const (
	ExitOK          = 0
	ExitFindings    = 1
	ExitUsage       = 2
	ExitFailure     = 3
	ExitInterrupted = 130
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
	// NewACM builds the ACM client of expirely aws; nil builds the real
	// one from the AWS configuration. Tests set it to a fake.
	NewACM func(ctx context.Context, profile, region string) (acm.API, string, error)
	// NewGCP builds the Compute client of expirely gcp; nil builds the real
	// one from Application Default Credentials. Tests point it at a fake.
	NewGCP func(ctx context.Context) (*gcp.Service, error)
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
  expirely aws [flags]
  expirely gcp [flags]

Commands
  expirely aws            list the certificates in AWS Certificate Manager; see expirely aws --help
  expirely gcp            list the certificates of a Google Cloud project; see expirely gcp --help

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
      --ca-file PATH      also trust the CA certificates in this PEM file

Output
      --json              print JSON; the default when stdout is not a terminal
      --details           add every certificate of each chain to the JSON
      --status LIST       show only these statuses: expired, expiring, error, ok, all
                          (default all; a declared agent gets expired,expiring,error)
      --fields LIST       keep only these keys in each JSON result; target is always kept
      --limit N           show at most N results, most urgent first
      --version           print the version
  -h, --help              show this help

Exit codes, over every result whatever --status, --fields and --limit show
  0 all ok, 1 expired or expiring, 2 usage error, 3 a target could not be read,
  130 stopped by Ctrl-C

Docs: https://github.com/bycavii/expirely-cli
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; errors go to
// stderr and exit with the code errorCodes assigns to them. When ctx is
// done before the work ends, as on Ctrl-C, Run prints no results and
// returns ExitInterrupted.
func Run(ctx context.Context, args []string, s Streams) int {
	if len(args) > 0 {
		switch args[0] {
		case "aws":
			return runAWS(ctx, args[1:], s)
		case "gcp":
			return runGCP(ctx, args[1:], s)
		}
	}
	return runScan(ctx, args, s)
}

// runScan probes the targets named in args and in --file.
func runScan(ctx context.Context, args []string, s Streams) int {
	c := newCommand(s, args, usage)
	fs := flag.NewFlagSet("expirely", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "")
	w := windowFlags(fs, defaultTimeout)
	concurrency := fs.Int("concurrency", defaultConcurrency, "")
	v := viewFlags(fs)
	fs.BoolVar(&v.details, "details", false, "")
	var files, caFiles fileList
	fs.Var(&caFiles, "ca-file", "")
	fs.Var(&files, "file", "")
	fs.Var(&files, "f", "")
	rest, code, done := c.parse(fs, args)
	if done {
		return code
	}

	if *showVersion {
		if c.json {
			return c.writeJSON(map[string]string{"version": version()})
		}
		fmt.Fprintf(c.Stdout, "expirely %s\n", version())
		return ExitOK
	}
	if e := w.check(); e != nil {
		return c.fail(e)
	}
	if e := v.resolve(c, fs); e != nil {
		return c.fail(e)
	}
	if *concurrency < 1 {
		return c.fail(failf(CodeInvalidFlag, "--concurrency must be 1 or more, got %d", *concurrency))
	}

	roots, e := loadRoots(caFiles)
	if e != nil {
		return c.fail(e)
	}
	targets, e := collectTargets(rest, files, c.Stdin)
	if e != nil {
		return c.fail(e)
	}
	if len(targets) == 0 {
		if len(files) > 0 {
			return c.fail(failf(CodeMissingArguments, "no targets in %s", strings.Join(fileNames(files), ", ")))
		}
		if !c.json && c.agent.Name == "" {
			fmt.Fprint(c.Stderr, intro)
			return errorCodes[CodeMissingArguments]
		}
		return c.fail(failf(CodeMissingArguments, "no targets: pass a host, host:port or https:// URL, or --file"))
	}

	start := time.Now()
	opts := scan.Options{Warn: w.warn(), Timeout: w.timeout, Now: start, Concurrency: *concurrency}
	var spinner *ui.Spinner
	if c.showsProgress() {
		spinner = ui.StartSpinner(c.Stderr, len(targets))
		opts.Progress = spinner.Done
	}
	findings, err := scan.Scan(ctx, probe.Prober{Roots: roots}, targets, opts)
	if spinner != nil {
		spinner.Stop()
	}
	if err != nil {
		return c.interrupted(err)
	}
	return c.report(newReport(start, w.warnDays, findings, v), time.Since(start))
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
// flags. An unknown flag is named as args gave it, since the flag package
// drops the dashes, and is followed by the closest flag fs defines, if
// suggest finds one: "-v" becomes "unknown flag -v; did you mean
// --version?". "flag needs an argument: -timeout" becomes "--timeout needs a
// value". Other messages are kept, with their flag names given two dashes.
func flagError(fs *flag.FlagSet, args []string, err error) string {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		text := "unknown flag " + typed(args, name)
		if s := suggest(fs, name); s != "" {
			text += "; did you mean --" + s + "?"
		}
		return text
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return "--" + strings.TrimPrefix(name, "-") + " needs a value"
	}
	return strings.Replace(msg, " flag -", " flag --", 1)
}

// typed returns the argument, up to any "=", that named the flag name, with
// the dashes it was given; "--" + name when no argument did.
func typed(args []string, name string) string {
	for _, a := range args {
		if a == "--" {
			break
		}
		flagPart, _, _ := strings.Cut(a, "=")
		if trimmed := strings.TrimLeft(flagPart, "-"); trimmed == name && flagPart != trimmed {
			return flagPart
		}
	}
	return "--" + name
}

// suggest returns the flag of fs closest to the unknown name: version for
// -v or -V, which people try for it, or the flag at the smallest edit
// distance when that distance is under half the name's length. It returns
// "" when no flag is that close.
func suggest(fs *flag.FlagSet, name string) string {
	lower := strings.ToLower(name)
	if lower == "v" && fs.Lookup("version") != nil {
		return "version"
	}
	best, bestDist := "", 0
	fs.VisitAll(func(f *flag.Flag) {
		d := editDistance(lower, f.Name)
		if 2*d < len(lower) && (best == "" || d < bestDist) {
			best, bestDist = f.Name, d
		}
	})
	return best
}

// editDistance is the Levenshtein distance between a and b, in bytes.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
