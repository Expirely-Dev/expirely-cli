package cli

import "fmt"

// Error codes are part of the public contract: scripts and agents match on
// them, so a code is never renamed or reused for a different failure. Every
// code is listed in the README.
const (
	CodeInvalidFlag      = "invalid_flag"
	CodeInvalidTarget    = "invalid_target"
	CodeMissingArguments = "missing_arguments"
	CodeFileUnreadable   = "file_unreadable"
	CodeOutputFailed     = "output_failed"
)

// errorCodes maps every error code to the exit code Run returns for it.
var errorCodes = map[string]int{
	CodeInvalidFlag:      ExitUsage,
	CodeInvalidTarget:    ExitUsage,
	CodeMissingArguments: ExitUsage,
	CodeFileUnreadable:   ExitUsage,
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
