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

func TestOldFormsStillWorkAndSayWhatReplacesThem(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"aws", "--region", "us-east-1"}, `"expirely aws" is now "expirely tls aws"`},
		{[]string{"-f", "missing.txt"}, `"expirely TARGET" is now "expirely tls TARGET"`},
	}
	for _, tt := range tests {
		_, _, stderr := route(t, nil, tt.args...)

		if !strings.HasPrefix(stderr, "expirely: "+tt.want+"; the old form stops working in expirely 1.0\n") {
			t.Errorf("expirely %q: stderr = %q, want the deprecation first", tt.args, stderr)
		}
	}

	code, stdout, _ := route(t, nil, "aws", "--region", "us-east-1", "--json")
	if code != ExitFindings || !json.Valid([]byte(stdout)) {
		t.Errorf("expirely aws = %d, stdout %q; want it to run as expirely tls aws, with stdout only the JSON report", code, stdout)
	}
}

func TestOldFormsAnnotateInGitHubActions(t *testing.T) {
	_, _, stderr := route(t, map[string]string{"GITHUB_ACTIONS": "true", "EXPIRELY_GITHUB": "0"}, "gcp", "--project", "")

	if !strings.HasPrefix(stderr, `::warning title=expirely::"expirely gcp" is now "expirely tls gcp"`) {
		t.Errorf("stderr = %q, want a warning annotation", stderr)
	}
}
