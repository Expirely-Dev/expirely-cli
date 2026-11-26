// Command expirely finds TLS certificates and reports when they expire.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/bycavii/expirely-cli/internal/cli"
	"github.com/bycavii/expirely-cli/internal/ui"
	"github.com/charmbracelet/colorprofile"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], cli.Streams{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		StdoutIsTerminal: isTerminal(os.Stdout),
		Style:            ui.Style{Profile: colorprofile.Detect(os.Stdout, os.Environ())},
	})
	stop()
	os.Exit(code)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
