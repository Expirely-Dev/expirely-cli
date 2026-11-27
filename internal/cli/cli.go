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

	"github.com/expirely-dev/expirely-cli/internal/acm"
	"github.com/expirely-dev/expirely-cli/internal/gcp"
	"github.com/expirely-dev/expirely-cli/internal/probe"
	"github.com/expirely-dev/expirely-cli/internal/scan"
	"github.com/expirely-dev/expirely-cli/internal/ui"
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
	// NewACM opens the AWS account expirely tls aws reads; nil opens the real
	// one from the AWS configuration. Tests set it to a fake.
	NewACM func(ctx context.Context, profile, region string) (acm.Account, error)
	// NewGCP builds the Compute client of expirely tls gcp; nil builds the real
	// one from Application Default Credentials. Tests point it at a fake.
	NewGCP func(ctx context.Context) (*gcp.Service, error)
}

const (
	defaultWarnDays    = 30
	defaultTimeout     = 10 * time.Second
	defaultConcurrency = 16
)

const tagline = "expirely tells you when your TLS certificates expire, before they break anything."

// rootUsage is the help of expirely itself, which only routes to its
// commands.
const rootUsage = tagline + `

Usage
  expirely <command> [flags]

Commands
  tls                     check the certificates TLS endpoints serve
  tls aws                 list the certificates in AWS Certificate Manager
  tls gcp                 list the certificates of a Google Cloud project

Examples
  expirely tls example.com api.example.com:8443
  expirely tls aws
  expirely tls gcp

Flags
      --version           print the version
  -h, --help              show this help

Each command lists its own flags with --help, such as expirely tls --help.

Docs: https://github.com/expirely-dev/expirely-cli
`

// intro is what a person sees when they run expirely tls with nothing to
// scan: a few ways in rather than every flag.
const intro = `expirely tls checks the certificates TLS endpoints serve.

  expirely tls example.com      check one host
  expirely tls -f hosts.txt     check a list, one per line
  expirely tls --help           every flag
`

const tlsUsage = `expirely tls checks the certificates TLS endpoints serve and when they expire.

Usage
  expirely tls [flags] TARGET...
  expirely tls [flags] -f FILE
  expirely tls aws [flags]
  expirely tls gcp [flags]

Commands
  expirely tls aws        list the certificates in AWS Certificate Manager; see expirely tls aws --help
  expirely tls gcp        list the certificates of a Google Cloud project; see expirely tls gcp --help

Examples
  expirely tls example.com api.example.com:8443
  expirely tls -f hosts.txt --warn-days 21
  cat hosts.txt | expirely tls -f - --json | jq .summary

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

Docs: https://github.com/expirely-dev/expirely-cli
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; errors go to
// stderr and exit with the code errorCodes assigns to them. When ctx is
// done before the work ends, as on Ctrl-C, Run prints no results and
// returns ExitInterrupted.
func Run(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(s.Stdout, rootUsage)
		return ExitOK
	}
	switch {
	case args[0] == "tls":
		return runTLS(ctx, args[1:], s)
	case args[0] == "aws" || args[0] == "gcp":
		deprecated(s, "expirely "+args[0], "expirely tls "+args[0])
		return runTLS(ctx, args, s)
	case onlyRootFlags(args):
		return runScan(ctx, args, s)
	}
	deprecated(s, "expirely TARGET", "expirely tls TARGET")
	return runScan(ctx, args, s)
}

// runTLS runs expirely tls: a scan of the targets in args, or, when args
// start with aws or gcp, the listing of that provider's certificates.
func runTLS(ctx context.Context, args []string, s Streams) int {
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

func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "-help" || arg == "--help"
}

// onlyRootFlags reports whether args hold only flags expirely itself
// takes, such as expirely --version --json, which are not a scan in the
// old form.
func onlyRootFlags(args []string) bool {
	for _, a := range args {
		switch a {
		case "--version", "-version", "--json", "-json", "--json=true", "-json=true", "--json=false", "-json=false":
		default:
			return false
		}
	}
	return true
}

// deprecated warns on stderr that the command old moved to replacement,
// as an annotation when expirely runs in GitHub Actions. The old forms
// stop working in 1.0.
func deprecated(s Streams, old, replacement string) {
	msg := fmt.Sprintf("%q is now %q; the old form stops working in expirely 1.0", old, replacement)
	if s.Getenv != nil && s.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Fprintf(s.Stderr, "::warning title=expirely::%s\n", workflowData(msg))
		return
	}
	fmt.Fprintf(s.Stderr, "expirely: %s\n", msg)
}

// runScan probes the targets named in args and in --file.
func runScan(ctx context.Context, args []string, s Streams) int {
	c := newCommand(s, args, tlsUsage)
	fs := flag.NewFlagSet("expirely tls", flag.ContinueOnError)
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
