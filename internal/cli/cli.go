// Package cli implements the expirely command line: it parses arguments,
// writes results to stdout and errors to stderr, and returns the process
// exit code instead of calling os.Exit, so tests drive it through Run.
//
// Output is JSON when --json is set or stdout is not a terminal, and text
// otherwise. Help is always text.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
)

// Exit codes returned by Run. ExitUsage covers flags and arguments the
// command does not accept; ExitFailure covers a command that was valid but
// could not finish, such as a failed write to stdout.
const (
	ExitOK      = 0
	ExitUsage   = 2
	ExitFailure = 3
)

// Streams holds the standard streams Run reads from and writes to.
// StdoutIsTerminal selects text output when --json is not set.
type Streams struct {
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	StdoutIsTerminal bool
}

const usage = `Usage: expirely [flags]

Find every TLS certificate you serve and when it expires.

Flags:
  -h, --help     show this help
      --json     print JSON; the default when stdout is not a terminal
      --version  print the version
`

// Run executes expirely with args, which exclude the program name, and
// returns the exit code. Help goes to stdout and exits ExitOK; errors go to
// stderr and exit with the code errorCodes assigns to them.
func Run(ctx context.Context, args []string, s Streams) int {
	_ = ctx
	jsonOut := !s.StdoutIsTerminal || wantsJSON(args)

	fs := flag.NewFlagSet("expirely", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	showVersion := fs.Bool("version", false, "")
	fs.Bool("json", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(s.Stdout, usage)
			return ExitOK
		}
		return fail(s, jsonOut, failf(CodeInvalidFlag, "%v", err))
	}

	if fs.NArg() > 0 {
		return fail(s, jsonOut, failf(CodeUnexpectedArgument, "unexpected argument %q", fs.Arg(0)))
	}

	if *showVersion {
		if jsonOut {
			return writeJSON(s, jsonOut, map[string]string{"version": version()})
		}
		fmt.Fprintf(s.Stdout, "expirely %s\n", version())
		return ExitOK
	}

	return fail(s, jsonOut, failf(CodeMissingArguments, "nothing to do: pass a flag"))
}

// wantsJSON reports whether args request JSON, read before flag parsing so
// that a parse error is already reported in the format the caller asked for.
func wantsJSON(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		return a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true"
	})
}

func fail(s Streams, jsonOut bool, e *Error) int {
	code := errorCodes[e.Code]
	if jsonOut {
		body := map[string]map[string]string{"error": {"message": e.Message, "code": e.Code}}
		if err := json.NewEncoder(s.Stderr).Encode(body); err != nil {
			fmt.Fprintf(s.Stderr, "expirely: %s (%s)\n", e.Message, e.Code)
		}
		return code
	}
	fmt.Fprintf(s.Stderr, "expirely: %s\n", e.Message)
	if code == ExitUsage {
		fmt.Fprintf(s.Stderr, "\n%s", usage)
	}
	return code
}

func writeJSON(s Streams, jsonOut bool, v any) int {
	if err := json.NewEncoder(s.Stdout).Encode(v); err != nil {
		return fail(s, jsonOut, failf(CodeOutputFailed, "write output: %v", err))
	}
	return ExitOK
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}
