package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/expirely-dev/expirely-cli/internal/tls/acm"
)

func route(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errOut,
		Getenv: envOf(env),
		NewACM: func(context.Context, string, string) (acm.Account, error) {
			return fakeAccount{region: "us-east-1", fallback: sampleACM()}, nil
		},
	})
	return code, out.String(), errOut.String()
}

func TestRootPrintsItsHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}} {
		code, stdout, stderr := route(t, nil, args...)

		if code != ExitOK || stdout != rootUsage || stderr != "" {
			t.Errorf("expirely %q = %d, stdout %q, stderr %q; want 0 and the root help", args, code, stdout, stderr)
		}
	}
}

func TestRootVersionIsNotAnOldScan(t *testing.T) {
	code, stdout, stderr := route(t, nil, "--version", "--json")

	if code != ExitOK || !strings.HasPrefix(stdout, `{"version":`) || stderr != "" {
		t.Errorf("expirely --version --json = %d, stdout %q, stderr %q; want the version and no warning", code, stdout, stderr)
	}
}

func TestTLSCommandsRunWithoutWarnings(t *testing.T) {
	tests := [][]string{
		{"tls", "--help"},
		{"tls", "aws", "--region", "us-east-1"},
	}
	for _, args := range tests {
		_, _, stderr := route(t, nil, args...)

		if strings.Contains(stderr, "is now") {
			t.Errorf("expirely %q warned %q; want no warning for the current form", args, stderr)
		}
	}
	if code, stdout, _ := route(t, nil, "tls", "--help"); code != ExitOK || stdout != tlsUsage {
		t.Errorf("expirely tls --help = %d, %q; want the tls help", code, stdout)
	}
}

func TestOldFormsAreUnknownCommands(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"aws", "--region", "us-east-1"}, `unknown command "aws"; did you mean "expirely tls aws"?`},
		{[]string{"gcp", "--project", "acme"}, `unknown command "gcp"; did you mean "expirely tls gcp"?`},
		{[]string{"example.com"}, `unknown command "example.com"; did you mean "expirely tls example.com"?`},
		{[]string{"-f", "targets.txt"}, `unknown flag -f; the flags of a check come after its command, as in "expirely tls -f"`},
		{[]string{"version"}, `unknown command "version"; did you mean "expirely --version"?`},
		{[]string{"tsl", "example.com"}, `unknown command "tsl"; did you mean "expirely tls"?`},
		{[]string{"completion"}, `unknown command "completion"`},
		{[]string{"-v"}, `unknown flag -v; did you mean --version?`},
		{[]string{"--vresion"}, `unknown flag --vresion; did you mean --version?`},
		{[]string{"--json", "example.com"}, `unknown command "example.com"; did you mean "expirely tls example.com"?`},
	}
	for _, tt := range tests {
		code, stdout, stderr := route(t, nil, tt.args...)

		var got envelope
		if err := json.Unmarshal([]byte(stderr), &got); err != nil {
			t.Fatalf("expirely %q: stderr = %q, want the JSON error envelope: %v", tt.args, stderr, err)
		}
		if code != ExitUsage || stdout != "" || got.Error.Message != tt.want {
			t.Errorf("expirely %q = %d, stdout %q, message %q; want exit 2 and %q", tt.args, code, stdout, got.Error.Message, tt.want)
		}
	}
}

func TestUnknownCommandInJSON(t *testing.T) {
	code, stdout, stderr := route(t, nil, "aws", "--json")

	var got envelope
	if err := json.Unmarshal([]byte(stderr), &got); err != nil {
		t.Fatalf("stderr = %q, want the JSON error envelope: %v", stderr, err)
	}
	if code != ExitUsage || stdout != "" || got.Error.Code != CodeUnknownCommand || got.Error.Remediation != remediations[CodeUnknownCommand] {
		t.Errorf("expirely aws --json = %d, stdout %q, error %+v; want exit 2 and code unknown_command with its remediation", code, stdout, got.Error)
	}
}

func TestUnknownCommandGivesAnAgentTheRootHelp(t *testing.T) {
	_, _, stderr := route(t, map[string]string{"AI_AGENT": "claude-code"}, "example.com")

	var got envelope
	if err := json.Unmarshal([]byte(stderr), &got); err != nil || got.Error.Usage != rootUsage {
		t.Errorf("stderr = %q, want the envelope with the root help in usage", stderr)
	}
}

func TestHelpIsACommandToo(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--json"}, rootUsage},
		{[]string{"help", "tls"}, tlsUsage},
		{[]string{"help", "tls", "aws"}, awsUsage},
		{[]string{"help", "tls", "gcp"}, gcpUsage},
		{[]string{"tls", "help"}, tlsUsage},
		{[]string{"tls", "help", "aws"}, awsUsage},
		{[]string{"tls", "aws", "help"}, awsUsage},
		{[]string{"tls", "gcp", "help"}, gcpUsage},
	}
	for _, tt := range tests {
		code, stdout, stderr := route(t, nil, tt.args...)

		if code != ExitOK || stdout != tt.want || stderr != "" {
			t.Errorf("expirely %q = %d, stdout %q, stderr %q; want 0 and that command's help", tt.args, code, stdout, stderr)
		}
	}

	code, _, stderr := route(t, nil, "help", "dns")
	var got envelope
	if err := json.Unmarshal([]byte(stderr), &got); err != nil || code != ExitUsage || got.Error.Code != CodeUnknownCommand {
		t.Errorf("expirely help dns = %d, stderr %q; want exit 2 and unknown_command", code, stderr)
	}
}

func TestAHostNamedHelpIsScannedAfterTheSeparator(t *testing.T) {
	_, stdout, _ := route(t, nil, "tls", "--timeout", "1ms", "--", "help")

	if !strings.Contains(stdout, `"target":"help:443"`) {
		t.Errorf("stdout = %q, want the host help scanned", stdout)
	}
}

func TestHelpFitsAnEightyColumnTerminal(t *testing.T) {
	for name, usage := range map[string]string{"expirely": rootUsage, "tls": tlsUsage, "tls aws": awsUsage, "tls gcp": gcpUsage, "intro": intro} {
		for line := range strings.SplitSeq(usage, "\n") {
			if len(line) > 80 {
				t.Errorf("the help of %s has a line of %d columns, over 80: %q", name, len(line), line)
			}
		}
	}
}

func TestHelpNamesEveryStatus(t *testing.T) {
	for _, s := range statusOrder {
		if !strings.Contains(viewUsage, string(s)) {
			t.Errorf("the --status help lacks %q", s)
		}
	}
}

func TestTextErrorsFitAnEightyColumnTerminal(t *testing.T) {
	for code := range errorCodes {
		var stderr bytes.Buffer
		c := &command{Streams: Streams{Stderr: &stderr}}

		c.fail(failf(code, "short message"))

		lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
		if lines[0] != "expirely: short message" {
			t.Errorf("%s: first line = %q, want the message", code, lines[0])
		}
		if len(lines) < 2 {
			t.Errorf("%s: stderr = %q, want the message and what resolves it", code, stderr.String())
		}
		for _, line := range lines {
			if len(line) > textWidth {
				t.Errorf("%s: a line of the text error has %d columns, over %d: %q", code, len(line), textWidth, line)
			}
		}
		if got := strings.Join(lines[1:], " "); got != remediations[code] {
			t.Errorf("%s: the wrapped remediation reads %q, want the words of %q", code, got, remediations[code])
		}
	}
}

func TestALongTextErrorMessageIsWrappedToo(t *testing.T) {
	var stderr bytes.Buffer
	c := &command{Streams: Streams{Stderr: &stderr}}

	c.fail(failf(CodeGCPNotConfigured, "no Google Cloud project: none in --project, GOOGLE_CLOUD_PROJECT or CLOUDSDK_CORE_PROJECT"))

	lines := strings.Split(stderr.String(), "\n")
	if lines[0] != "expirely: no Google Cloud project: none in --project, GOOGLE_CLOUD_PROJECT or" || lines[1] != "CLOUDSDK_CORE_PROJECT" {
		t.Errorf("stderr = %q, want the message wrapped at %d columns", stderr.String(), textWidth)
	}
}
