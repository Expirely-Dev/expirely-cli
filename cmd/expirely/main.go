// Command expirely finds TLS certificates and reports when they expire.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"
	"github.com/expirely-dev/expirely-cli/internal/cli"
	"github.com/expirely-dev/expirely-cli/internal/ui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	context.AfterFunc(ctx, stop)
	code := cli.Run(ctx, os.Args[1:], cli.Streams{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		StdoutIsTerminal: term.IsTerminal(os.Stdout.Fd()),
		StderrIsTerminal: term.IsTerminal(os.Stderr.Fd()) && os.Getenv("TERM") != "dumb",
		Style:            ui.Style{Profile: colorprofile.Detect(os.Stdout, os.Environ())},
		Getenv:           os.Getenv,
	})
	stop()
	os.Exit(code)
}
