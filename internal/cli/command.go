package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
)

// command is one run of expirely or of a subcommand: the streams it writes
// to, the agent reading them, and whether it reports in JSON. Every command
// parses, fails and reports through it, so they all follow the same output
// contract.
type command struct {
	Streams
	agent agent
	json  bool
	help  string
}

// newCommand prepares a command with help as its usage text. A detected
// agent gets no color; a declared one, or a stdout that is not a terminal,
// gets JSON. The --json flag, once parsed, overrides that choice.
func newCommand(s Streams, args []string, help string) *command {
	ag := detectAgent(s.Getenv, s.StdoutIsTerminal)
	if ag.Name != "" {
		s.Style = ui.Style{}
	}
	return &command{
		Streams: s,
		agent:   ag,
		json:    !s.StdoutIsTerminal || ag.Declared || wantsJSON(args),
		help:    help,
	}
}

// parse defines --json on fs and parses args, with flags before, between
// or after the other arguments, which it returns in order; everything after
// "--" is an argument. It returns done with the exit code when the command
// is over: after printing the help for -h, or after reporting a flag error.
func (c *command) parse(fs *flag.FlagSet, args []string) (rest []string, code int, done bool) {
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(c.Stdout, c.help)
			return nil, ExitOK, true
		}
		return nil, c.fail(failf(CodeInvalidFlag, "%s", flagError(err))), true
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" {
			c.json = *jsonFlag
		}
	})
	return rest, ExitOK, false
}

// parseInterspersed parses args with fs as people type them in gh or
// kubectl: the flag package stops at the first argument that is not a
// flag, so parsing resumes after each one until "--" or the end.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		left := fs.Args()
		if consumed := len(args) - len(left); consumed > 0 && args[consumed-1] == "--" {
			return append(rest, left...), nil
		}
		if len(left) == 0 {
			return rest, nil
		}
		rest = append(rest, left[0])
		args = left[1:]
	}
}

// fail prints e and returns its exit code. In JSON it prints the envelope;
// in text it prints the message and, on the next line, what resolves it.
// A usage error read by an agent also gets the whole help, since an agent
// cannot ask for --help the way a person glances at it.
func (c *command) fail(e *Error) int {
	code := errorCodes[e.Code]
	var help string
	if c.agent.Name != "" && code == ExitUsage {
		help = c.help
	}
	if c.json {
		var body envelope
		body.Error.Code = e.Code
		body.Error.Message = e.Message
		body.Error.Remediation = remediations[e.Code]
		body.Error.Usage = help
		if err := json.NewEncoder(c.Stderr).Encode(body); err != nil {
			fmt.Fprintf(c.Stderr, "expirely: %s (%s)\n", e.Message, e.Code)
		}
		return code
	}
	fmt.Fprintf(c.Stderr, "expirely: %s\n%s\n", ui.Clean(e.Message), remediations[e.Code])
	if help != "" {
		fmt.Fprintf(c.Stderr, "\n%s", help)
	}
	return code
}

// showsProgress reports whether a spinner may be drawn on stderr: only
// for a person, at a terminal.
func (c *command) showsProgress() bool {
	return c.StderrIsTerminal && c.agent.Name == ""
}

// waiting draws a spinner labeled label while work of unknown size runs,
// when showsProgress allows one, and returns the function that erases it.
func (c *command) waiting(label string) (stop func()) {
	if !c.showsProgress() {
		return func() {}
	}
	return ui.StartWaiting(c.Stderr, label).Stop
}

// interrupted reports a command stopped by its context, such as by
// Ctrl-C, and returns ExitInterrupted.
func (c *command) interrupted(err error) int {
	return c.fail(failf(CodeInterrupted, "stopped before the end: %v", err))
}

func (c *command) writeJSON(v any) int {
	if err := json.NewEncoder(c.Stdout).Encode(v); err != nil {
		return c.fail(failf(CodeOutputFailed, "write output: %v", err))
	}
	return ExitOK
}

// report prints r, in JSON or as text with the time the work took, and
// returns the exit code every result calls for, shown or not: --status,
// --limit and --fields change what is printed, never what fails.
func (c *command) report(r report, elapsed time.Duration) int {
	if c.json {
		if code := c.writeJSON(r); code != ExitOK {
			return code
		}
	} else {
		writeText(c.Style.Writer(c.Stdout), c.Style, r, elapsed)
	}
	return exitCode(r.all)
}

// envelope is the JSON a command error prints on stderr. Usage holds the
// whole help, only for a usage error read by an agent.
type envelope struct {
	Error struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		Remediation string `json:"remediation"`
		Usage       string `json:"usage,omitempty"`
	} `json:"error"`
}

// window is the flags every command that reports expiry takes: how close
// to expiry a certificate counts as expiring, and how long the work may
// take.
type window struct {
	warnDays int
	timeout  time.Duration
}

// windowFlags defines --warn-days and --timeout on fs.
func windowFlags(fs *flag.FlagSet, timeout time.Duration) *window {
	w := &window{}
	fs.IntVar(&w.warnDays, "warn-days", defaultWarnDays, "")
	fs.DurationVar(&w.timeout, "timeout", timeout, "")
	return w
}

func (w *window) check() *Error {
	if w.warnDays < 0 {
		return failf(CodeInvalidFlag, "--warn-days must be 0 or more, got %d", w.warnDays)
	}
	if w.timeout <= 0 {
		return failf(CodeInvalidFlag, "--timeout must be positive, got %s", w.timeout)
	}
	return nil
}

func (w *window) warn() time.Duration { return time.Duration(w.warnDays) * 24 * time.Hour }

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
