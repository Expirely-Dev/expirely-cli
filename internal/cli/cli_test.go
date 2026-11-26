package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/tlstest"
)

func run(t *testing.T, terminal bool, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
	})
	return code, out.String(), errOut.String()
}

func TestRunText(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no targets prints usage to stderr",
			wantCode:   ExitUsage,
			wantStderr: "expirely: no targets: pass a host, host:port or https:// URL, or --file\n\nUsage: expirely",
		},
		{
			name:       "help prints usage to stdout",
			args:       []string{"--help"},
			wantCode:   ExitOK,
			wantStdout: "Usage: expirely",
		},
		{
			name:       "version prints the build version",
			args:       []string{"--version"},
			wantCode:   ExitOK,
			wantStdout: "expirely ",
		},
		{
			name:       "unknown flag is a usage error",
			args:       []string{"--nope"},
			wantCode:   ExitUsage,
			wantStderr: "expirely: flag provided but not defined: -nope\n\nUsage: expirely",
		},
		{
			name:       "invalid target is a usage error",
			args:       []string{"http://example.com"},
			wantCode:   ExitUsage,
			wantStderr: `expirely: invalid target "http://example.com": scheme "http" does not use TLS`,
		},
		{
			name:       "negative warn days is a usage error",
			args:       []string{"--warn-days", "-1", "example.com"},
			wantCode:   ExitUsage,
			wantStderr: "expirely: --warn-days must be 0 or more, got -1",
		},
		{
			name:       "zero timeout is a usage error",
			args:       []string{"--timeout", "0s", "example.com"},
			wantCode:   ExitUsage,
			wantStderr: "expirely: --timeout must be positive, got 0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, true, tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.HasPrefix(stdout, tt.wantStdout) || (tt.wantStdout == "" && stdout != "") {
				t.Errorf("stdout = %q, want prefix %q", stdout, tt.wantStdout)
			}
			if !strings.HasPrefix(stderr, tt.wantStderr) || (tt.wantStderr == "" && stderr != "") {
				t.Errorf("stderr = %q, want prefix %q", stderr, tt.wantStderr)
			}
		})
	}
}

func TestRunJSONErrors(t *testing.T) {
	tests := []struct {
		name     string
		terminal bool
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "stdout not a terminal", terminal: false, args: []string{"--nope"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
		{name: "json flag after a bad flag", terminal: true, args: []string{"--nope", "--json"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
		{name: "invalid target", terminal: true, args: []string{"--json", "example.com:0"}, wantCode: ExitUsage, wantErr: CodeInvalidTarget},
		{name: "no targets", terminal: false, wantCode: ExitUsage, wantErr: CodeMissingArguments},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.terminal, tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			var got struct {
				Error struct {
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stderr), &got); err != nil {
				t.Fatalf("stderr is not the JSON error envelope: %v\n%s", err, stderr)
			}
			if got.Error.Code != tt.wantErr {
				t.Errorf("error code = %q, want %q", got.Error.Code, tt.wantErr)
			}
			if got.Error.Message == "" {
				t.Error("error message is empty")
			}
		})
	}
}

func TestRunJSONVersion(t *testing.T) {
	code, stdout, stderr := run(t, false, "--version")

	if code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if got["version"] == "" {
		t.Errorf("version = %q, want non-empty", got["version"])
	}
}

type scanReport struct {
	WarnDays int            `json:"warn_days"`
	Summary  map[string]int `json:"summary"`
	Results  []struct {
		Target   string `json:"target"`
		Status   string `json:"status"`
		DaysLeft *int   `json:"days_left"`
		Trusted  *bool  `json:"trusted"`
		Leaf     *any   `json:"leaf"`
		Error    *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"results"`
}

func TestRunScanJSON(t *testing.T) {
	ca := tlstest.NewCA(t)
	day := 24 * time.Hour
	healthy := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*day)))
	expiring := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(5*day+time.Hour)))
	expired := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(-time.Hour)))
	closed := tlstest.ClosedPort(t)

	tests := []struct {
		name       string
		ports      []int
		wantCode   int
		wantStatus []string
		wantDays   []int
	}{
		{name: "all ok", ports: []int{healthy}, wantCode: ExitOK, wantStatus: []string{"ok"}, wantDays: []int{89}},
		{name: "expiring wins over ok", ports: []int{healthy, expiring}, wantCode: ExitFindings, wantStatus: []string{"ok", "expiring"}, wantDays: []int{89, 5}},
		{name: "expired is a finding", ports: []int{expired}, wantCode: ExitFindings, wantStatus: []string{"expired"}, wantDays: []int{-1}},
		{name: "unreadable target", ports: []int{healthy, closed}, wantCode: ExitFailure, wantStatus: []string{"ok", "error"}, wantDays: []int{89, 0}},
		{name: "finding wins over unreadable", ports: []int{closed, expired}, wantCode: ExitFindings, wantStatus: []string{"error", "expired"}, wantDays: []int{0, -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--timeout", "2s"}
			for _, p := range tt.ports {
				args = append(args, fmt.Sprintf("localhost:%d", p))
			}
			code, stdout, stderr := run(t, false, args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
			var got scanReport
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("stdout is not the JSON report: %v\n%s", err, stdout)
			}
			if got.WarnDays != defaultWarnDays {
				t.Errorf("warn_days = %d, want %d", got.WarnDays, defaultWarnDays)
			}
			if len(got.Results) != len(tt.ports) {
				t.Fatalf("len(results) = %d, want %d", len(got.Results), len(tt.ports))
			}
			for i, r := range got.Results {
				if want := fmt.Sprintf("localhost:%d", tt.ports[i]); r.Target != want {
					t.Errorf("results[%d].target = %q, want %q (input order)", i, r.Target, want)
				}
				if r.Status != tt.wantStatus[i] {
					t.Errorf("results[%d].status = %q, want %q", i, r.Status, tt.wantStatus[i])
				}
				if r.Status == "error" {
					if r.DaysLeft != nil || r.Trusted != nil || r.Leaf != nil {
						t.Errorf("results[%d] error has certificate fields, want null", i)
					}
					if r.Error == nil || r.Error.Code != "dial_failed" {
						t.Errorf("results[%d].error = %+v, want code dial_failed", i, r.Error)
					}
					continue
				}
				if r.DaysLeft == nil || *r.DaysLeft != tt.wantDays[i] {
					t.Errorf("results[%d].days_left = %v, want %d", i, r.DaysLeft, tt.wantDays[i])
				}
				if r.Trusted == nil || *r.Trusted {
					t.Errorf("results[%d].trusted = %v, want false for a test CA", i, r.Trusted)
				}
			}
			if got.Summary[tt.wantStatus[0]] == 0 {
				t.Errorf("summary = %v, want a count for %q", got.Summary, tt.wantStatus[0])
			}
		})
	}
}

func TestRunScanText(t *testing.T) {
	ca := tlstest.NewCA(t)
	healthy := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*24*time.Hour)))
	expired := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(-time.Hour)))

	code, stdout, _ := run(t, true, fmt.Sprintf("localhost:%d", healthy), fmt.Sprintf("localhost:%d", expired))

	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	lines := strings.Split(stdout, "\n")
	if !strings.HasPrefix(lines[0], "TARGET") {
		t.Fatalf("first line = %q, want the table header", lines[0])
	}
	if !strings.Contains(lines[1], "expired") || !strings.Contains(lines[2], "ok") {
		t.Errorf("rows = %q, %q, want the expired row first", lines[1], lines[2])
	}
	if !strings.Contains(stdout, "2 targets: 1 expired, 0 expiring, 0 unreadable, 1 ok") {
		t.Errorf("stdout = %q, want the summary line", stdout)
	}
}

func TestCommonName(t *testing.T) {
	tests := map[string]string{
		"CN=R11,O=Let's Encrypt,C=US": "R11",
		"CN=only":                     "only",
		`CN=a\,b,O=x`:                 `a\,b`,
		"O=No CN,C=US":                "O=No CN,C=US",
	}
	for dn, want := range tests {
		if got := commonName(dn); got != want {
			t.Errorf("commonName(%q) = %q, want %q", dn, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	if got := clean("ok\x1b[31mred\x07\n"); got != "ok[31mred" {
		t.Errorf("clean() = %q, want control characters removed", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: failingWriter{},
		Stderr: &stderr,
	})

	if code != ExitFailure {
		t.Errorf("exit code = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), `"code":"output_failed"`) {
		t.Errorf("stderr = %q, want the output_failed code", stderr.String())
	}
}

func TestFailfRejectsUnknownCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("failf with an unknown code did not panic")
		}
	}()
	_ = failf("no_such_code", "x")
}

func readDoc(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "src", "content", "docs", "reference", name)) //nolint:gosec // G304: name is a fixed page name from the tests.
	if err != nil {
		t.Fatalf("read reference page: %v", err)
	}
	return doc
}

func TestDocsListEveryCode(t *testing.T) {
	doc := readDoc(t, "codes.mdx")
	codes := []string{scan.CodeDialFailed, scan.CodeHandshakeFailed}
	for code := range errorCodes {
		codes = append(codes, code)
	}
	for _, code := range codes {
		if !bytes.Contains(doc, []byte("| `"+code+"` |")) {
			t.Errorf("reference/codes.mdx has no table row for code %q", code)
		}
	}
}

func TestDocsListEveryFlag(t *testing.T) {
	doc := readDoc(t, "cli.mdx")
	flags := regexp.MustCompile(`--[a-z][a-z-]*`).FindAllString(usage, -1)
	if len(flags) == 0 {
		t.Fatal("found no flags in the usage text")
	}
	for _, f := range flags {
		row := regexp.MustCompile("(?m)^\\|[^|\\n]*`" + regexp.QuoteMeta(f) + "[ `]")
		if !row.Match(doc) {
			t.Errorf("reference/cli.mdx has no table row for %s from the usage text", f)
		}
	}
}

func TestVersionPrefersBuildVersion(t *testing.T) {
	t.Cleanup(func() { buildVersion = "" })
	buildVersion = "v1.2.3"

	if got := version(); got != "v1.2.3" {
		t.Errorf("version() = %q, want the ldflags value v1.2.3", got)
	}
}
