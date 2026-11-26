// Package cli implements the expirely command line: it parses arguments,
// writes results to stdout and errors to stderr, and returns the process
// exit code instead of calling os.Exit, so tests drive it through Run.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
)

// Exit codes returned by Run. ExitUsage covers unknown flags and arguments
// the command does not accept.
const (
	ExitOK    = 0
	ExitUsage = 2
)

// Streams holds the standard streams Run reads from and writes to.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

const usage = `Usage: expirely [flags]

Find every TLS certificate you serve and when it expires.

Flags:
  -h, --help     show this help
      --version  print the version
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; usage errors
// go to stderr and exit ExitUsage.
func Run(ctx context.Context, args []string, s Streams) int {
	_ = ctx
	fs := flag.NewFlagSet("expirely", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	showVersion := fs.Bool("version", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, usage)
			return ExitOK
		}
		fmt.Fprintf(s.Stderr, "expirely: %v\n\n%s", err, usage)
		return ExitUsage
	}

	if *showVersion {
		fmt.Fprintf(s.Stdout, "expirely %s\n", version())
		return ExitOK
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(s.Stderr, "expirely: unexpected argument %q\n\n%s", fs.Arg(0), usage)
		return ExitUsage
	}

	fmt.Fprint(s.Stderr, usage)
	return ExitUsage
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}
