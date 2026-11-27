package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/expirely-dev/expirely-cli/internal/acm"
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
		{[]string{"-f", "targets.txt"}, `unknown command "-f"; did you mean "expirely tls -f"?`},
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
