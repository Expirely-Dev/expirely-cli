package cli

import "fmt"

// Error codes are part of the public contract: scripts and agents match on
// them, so a code is never renamed or reused for a different failure. Every
// code is listed in docs/cli/reference/error-codes.mdx.
const (
	CodeInvalidFlag        = "invalid_flag"
	CodeUnknownCommand     = "unknown_command"
	CodeUnexpectedArgument = "unexpected_argument"
	CodeInvalidTarget      = "invalid_target"
	CodeMissingArguments   = "missing_arguments"
	CodeFileUnreadable     = "file_unreadable"
	CodeInvalidCAFile      = "invalid_ca_file"
	CodeAWSNotConfigured   = "aws_not_configured"
	CodeAWSAccessDenied    = "aws_access_denied"
	CodeAWSRequestFailed   = "aws_request_failed"
	CodeGCPNotConfigured   = "gcp_not_configured"
	CodeGCPAccessDenied    = "gcp_access_denied"
	CodeGCPComputeDisabled = "gcp_compute_disabled"
	CodeInterrupted        = "interrupted"
	CodeGCPRequestFailed   = "gcp_request_failed"
	CodeOutputFailed       = "output_failed"
)

// causes says, for every error code, what went wrong, in one sentence. The
// manifest carries them, and the documentation site renders its table of
// error codes from it.
var causes = map[string]string{
	CodeInvalidFlag:        "A flag is unknown or has a value it does not take.",
	CodeUnknownCommand:     "The first argument is not a command, or expirely help got a command there is no help for.",
	CodeUnexpectedArgument: "expirely tls aws or expirely tls gcp got an argument that is not a flag, such as a target.",
	CodeInvalidTarget:      "A target is not a host, host:port or https:// URL.",
	CodeMissingArguments:   "No target was given in the arguments or files.",
	CodeFileUnreadable:     "A --file could not be opened or read, or has a line over 64 KiB.",
	CodeInvalidCAFile:      "A --ca-file could not be read, holds no PEM certificate, or holds one that does not parse.",
	CodeAWSNotConfigured:   "expirely tls aws found no region in --region, AWS_REGION or the profile, or the profile does not exist in the shared AWS config.",
	CodeAWSAccessDenied:    "AWS refused the credentials, they expired, or they lack the ACM read permissions.",
	CodeAWSRequestFailed:   "Another AWS failure, such as a timeout or a throttled request.",
	CodeGCPNotConfigured:   "expirely tls gcp found no project, or no Application Default Credentials.",
	CodeGCPAccessDenied:    "Google Cloud refused the credentials, or they lack the Compute or Certificate Manager list permissions.",
	CodeGCPComputeDisabled: "The project has the Compute Engine API or billing disabled, so it serves no Compute SSL certificates.",
	CodeGCPRequestFailed:   "Another Google Cloud failure, such as a timeout or a server error.",
	CodeInterrupted:        "The run was stopped, as Ctrl-C does, before it ended; it printed no results, since partial ones would read as complete.",
	CodeOutputFailed:       "Writing the result to stdout failed, for example a closed pipe.",
}

// exitMeanings says what each exit code of Run means.
var exitMeanings = map[int]string{
	ExitOK:          "Every result is ok, or --help or --version ran.",
	ExitFindings:    "At least one certificate is expired, revoked or expiring.",
	ExitUsage:       "Usage error: unknown command, bad flag, invalid target, unreadable --file or no targets.",
	ExitFailure:     "At least one target could not be read, an end date is unknown, a cloud command could not read every region, or writing the output failed.",
	ExitInterrupted: "Stopped by Ctrl-C before the end; no results were printed.",
}

// remediations says, for every error code, what resolves it. They are
// declarative and never repeat what the user typed: an agent reads them as
// facts about the tool, not as instructions from it.
var remediations = map[string]string{
	CodeInvalidFlag:        "Each command lists every flag and the values it accepts in its --help.",
	CodeUnknownCommand:     "expirely --help lists the commands; checks run under expirely tls, such as expirely tls example.com, expirely tls aws and expirely tls gcp.",
	CodeUnexpectedArgument: "expirely tls aws and expirely tls gcp read a whole account or project and take flags only; targets go to expirely tls.",
	CodeInvalidTarget:      "A target is host, host:port, [ipv6]:port or https://host/path; the port defaults to 443.",
	CodeMissingArguments:   "Targets come as arguments, such as expirely tls example.com, or one per line from --file.",
	CodeFileUnreadable:     "A --file needs to exist, be readable and hold one target per line of at most 64 KiB; - reads stdin.",
	CodeInvalidCAFile:      "A --ca-file is a readable PEM file with one or more CERTIFICATE blocks, such as an internal CA's root.",
	CodeAWSNotConfigured:   "expirely tls aws reads the profile from --profile or AWS_PROFILE and the region from --region, AWS_REGION or that profile, as the AWS CLI does.",
	CodeAWSAccessDenied:    "The credentials were refused, expired or lack acm:ListCertificates and acm:DescribeCertificate in this account and region, or ec2:DescribeRegions for --region all.",
	CodeAWSRequestFailed:   "ACM did not answer as expected; the message has its reason, and a later run or a longer --timeout often succeeds.",
	CodeGCPNotConfigured:   "expirely tls gcp reads the project from --project, GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT and signs in with Application Default Credentials, as gcloud auth application-default login sets up.",
	CodeGCPAccessDenied:    "The credentials were refused or lack compute.sslCertificates.list, compute.targetHttpsProxies.list, compute.targetSslProxies.list, certificatemanager.locations.list or certificatemanager.certs.list in this project.",
	CodeGCPComputeDisabled: "Google Cloud reports the Compute Engine API or billing disabled in this project, so the project serves no Compute SSL certificates.",
	CodeGCPRequestFailed:   "Google Cloud did not answer as expected; the message has its reason, and a later run or a longer --timeout often succeeds.",
	CodeInterrupted:        "The run was stopped, as Ctrl-C does, before it ended; it printed no results, since partial ones would read as complete.",
	CodeOutputFailed:       "The reader of stdout closed before the output ended, as a pipe to head does; the scan itself finished.",
}

// errorCodes maps every error code to the exit code Run returns for it.
var errorCodes = map[string]int{
	CodeInvalidFlag:        ExitUsage,
	CodeUnknownCommand:     ExitUsage,
	CodeUnexpectedArgument: ExitUsage,
	CodeInvalidTarget:      ExitUsage,
	CodeMissingArguments:   ExitUsage,
	CodeFileUnreadable:     ExitUsage,
	CodeInvalidCAFile:      ExitUsage,
	CodeAWSNotConfigured:   ExitUsage,
	CodeAWSAccessDenied:    ExitFailure,
	CodeAWSRequestFailed:   ExitFailure,
	CodeGCPNotConfigured:   ExitUsage,
	CodeGCPAccessDenied:    ExitFailure,
	CodeGCPComputeDisabled: ExitFailure,
	CodeGCPRequestFailed:   ExitFailure,
	CodeInterrupted:        ExitInterrupted,
	CodeOutputFailed:       ExitFailure,
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
