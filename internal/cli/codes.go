package cli

import "fmt"

// Error codes are part of the public contract: scripts and agents match on
// them, so a code is never renamed or reused for a different failure. Every
// code is listed in docs/reference/error-codes.mdx.
const (
	CodeInvalidFlag      = "invalid_flag"
	CodeInvalidTarget    = "invalid_target"
	CodeMissingArguments = "missing_arguments"
	CodeFileUnreadable   = "file_unreadable"
	CodeInvalidCAFile    = "invalid_ca_file"
	CodeOutputFailed     = "output_failed"
)

// remediations says, for every error code, what resolves it. They are
// declarative and never repeat what the user typed: an agent reads them as
// facts about the tool, not as instructions from it.
var remediations = map[string]string{
	CodeInvalidFlag:      "expirely --help lists every flag and the values it accepts.",
	CodeInvalidTarget:    "A target is host, host:port, [ipv6]:port or https://host/path; the port defaults to 443.",
	CodeMissingArguments: "Targets come as arguments, such as expirely example.com, or one per line from --file.",
	CodeFileUnreadable:   "A --file needs to exist, be readable and hold one target per line of at most 64 KiB; - reads stdin.",
	CodeInvalidCAFile:    "A --ca-file is a readable PEM file with one or more CERTIFICATE blocks, such as an internal CA's root.",
	CodeOutputFailed:     "The reader of stdout closed before the output ended, as a pipe to head does; the scan itself finished.",
}

// errorCodes maps every error code to the exit code Run returns for it.
var errorCodes = map[string]int{
	CodeInvalidFlag:      ExitUsage,
	CodeInvalidTarget:    ExitUsage,
	CodeMissingArguments: ExitUsage,
	CodeFileUnreadable:   ExitUsage,
	CodeInvalidCAFile:    ExitUsage,
	CodeOutputFailed:     ExitFailure,
}

// Error is a command failure with a stable Code from errorCodes and a
// Message for people.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// failf builds an Error. It panics when code is missing from errorCodes,
// which is a programming error caught by the tests.
func failf(code, format string, args ...any) *Error {
	if _, ok := errorCodes[code]; !ok {
		panic(fmt.Sprintf("cli: error code %q is not in errorCodes", code))
	}
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
