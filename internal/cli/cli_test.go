package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
			name:       "no targets shows a short intro, not the whole help",
			wantCode:   ExitUsage,
			wantStderr: intro,
		},
		{
			name:       "help prints usage to stdout",
			args:       []string{"--help"},
			wantCode:   ExitOK,
			wantStdout: usage,
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
			wantStderr: "expirely: unknown flag --nope\nexpirely --help lists every flag and the values it accepts.\n",
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
		wantOrder  []int
		wantStatus []string
		wantDays   []int
	}{
		{name: "all ok", ports: []int{healthy}, wantCode: ExitOK, wantOrder: []int{0}, wantStatus: []string{"ok"}, wantDays: []int{89}},
		{name: "expiring wins over ok", ports: []int{healthy, expiring}, wantCode: ExitFindings, wantOrder: []int{1, 0}, wantStatus: []string{"expiring", "ok"}, wantDays: []int{5, 89}},
		{name: "expired is a finding", ports: []int{expired}, wantCode: ExitFindings, wantOrder: []int{0}, wantStatus: []string{"expired"}, wantDays: []int{-1}},
		{name: "unreadable target", ports: []int{healthy, closed}, wantCode: ExitFailure, wantOrder: []int{1, 0}, wantStatus: []string{"error", "ok"}, wantDays: []int{0, 89}},
		{name: "finding wins over unreadable", ports: []int{closed, expired}, wantCode: ExitFindings, wantOrder: []int{1, 0}, wantStatus: []string{"expired", "error"}, wantDays: []int{-1, 0}},
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
				if want := fmt.Sprintf("localhost:%d", tt.ports[tt.wantOrder[i]]); r.Target != want {
					t.Errorf("results[%d].target = %q, want %q (most urgent first)", i, r.Target, want)
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

func TestRunShowsProgressOnlyOnATerminal(t *testing.T) {
	release := make(chan struct{})
	slow := tlstest.Serve(t, func(net.Conn) { <-release })
	t.Cleanup(func() { close(release) })
	args := []string{"--timeout", "400ms", fmt.Sprintf("localhost:%d", slow)}

	for _, terminal := range []bool{true, false} {
		var stdout, stderr bytes.Buffer
		Run(context.Background(), args, Streams{
			Stdin:            strings.NewReader(""),
			Stdout:           &stdout,
			Stderr:           &stderr,
			StdoutIsTerminal: true,
			StderrIsTerminal: terminal,
		})

		switch {
		case terminal && !strings.Contains(stderr.String(), "Scanning 1 target"):
			t.Errorf("stderr on a terminal = %q, want the spinner", stderr.String())
		case terminal && !strings.HasSuffix(stderr.String(), "\r\x1b[2K"):
			t.Errorf("stderr on a terminal = %q, want the spinner line erased at the end", stderr.String())
		case !terminal && stderr.Len() != 0:
			t.Errorf("stderr without a terminal = %q, want nothing", stderr.String())
		}
		if strings.Contains(stdout.String(), "Scanning") {
			t.Errorf("stdout = %q, want the spinner kept off stdout", stdout.String())
		}
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
	if len(lines) < 5 || lines[0] != "" {
		t.Fatalf("stdout = %q, want a blank line, two rows, a blank line and a summary", stdout)
	}
	if !strings.HasPrefix(lines[1], "  expired  localhost:") || !strings.HasPrefix(lines[2], "  ok       localhost:") {
		t.Errorf("rows = %q, %q, want the expired row first", lines[1], lines[2])
	}
	if !strings.HasPrefix(lines[4], "  1 expired, 1 ok in ") {
		t.Errorf("summary = %q, want counts and the elapsed time", lines[4])
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Errorf("stdout = %q, want no escape codes from a zero Style", stdout)
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
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", name)) //nolint:gosec // G304: name is a fixed page name from the tests.
	if err != nil {
		t.Fatalf("read docs page: %v", err)
	}
	return doc
}

func TestDocsListEveryCode(t *testing.T) {
	doc := readDoc(t, filepath.Join("reference", "error-codes.mdx"))
	codes := []string{scan.CodeDialFailed, scan.CodeHandshakeFailed}
	for code := range errorCodes {
		codes = append(codes, code)
	}
	for _, code := range codes {
		if !bytes.Contains(doc, []byte("| `"+code+"` |")) {
			t.Errorf("docs/reference/error-codes.mdx has no table row for code %q", code)
		}
	}
}

func TestDocsListEveryFlag(t *testing.T) {
	pages := []struct {
		help string
		page string
	}{
		{usage, filepath.Join("cli", "expirely.mdx")},
		{awsUsage, filepath.Join("cli", "aws.mdx")},
		{gcpUsage, filepath.Join("cli", "gcp.mdx")},
	}
	for _, p := range pages {
		doc := readDoc(t, p.page)
		flags := regexp.MustCompile(`--[a-z][a-z-]*`).FindAllString(p.help, -1)
		if len(flags) == 0 {
			t.Fatalf("found no flags in the help for %s", p.page)
		}
		for _, f := range flags {
			row := regexp.MustCompile("(?m)^\\|[^|\\n]*`" + regexp.QuoteMeta(f) + "[ `]")
			if !row.Match(doc) {
				t.Errorf("docs/%s has no table row for %s from its help", p.page, f)
			}
		}
	}
}

func TestFlagError(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--nope"}, "unknown flag --nope"},
		{[]string{"-nope"}, "unknown flag -nope"},
		{[]string{"-v"}, "unknown flag -v; did you mean --version?"},
		{[]string{"-V"}, "unknown flag -V; did you mean --version?"},
		{[]string{"--limt", "3", "example.com"}, "unknown flag --limt; did you mean --limit?"},
		{[]string{"--warn-day=21", "example.com"}, "unknown flag --warn-day; did you mean --warn-days?"},
		{[]string{"example.com", "--jsn"}, "unknown flag --jsn; did you mean --json?"},
		{[]string{"--nope", "--", "--nope"}, "unknown flag --nope"},
		{[]string{"aws", "-v"}, "unknown flag -v"},
		{[]string{"gcp", "--projet", "x"}, "unknown flag --projet; did you mean --project?"},
		{[]string{"--warn-days", "x"}, `invalid value "x" for flag --warn-days: parse error`},
		{[]string{"--timeout"}, "--timeout needs a value"},
	}
	for _, tt := range tests {
		_, _, stderr := run(t, true, tt.args...)
		if !strings.HasPrefix(stderr, "expirely: "+tt.want+"\n") {
			t.Errorf("args %q: stderr = %q, want message %q", tt.args, stderr, tt.want)
		}
	}
}

func TestFlagSuggestionReachesAgents(t *testing.T) {
	_, stdout, stderr := run(t, false, "-v")

	var got envelope
	if err := json.Unmarshal([]byte(stderr), &got); err != nil {
		t.Fatalf("stderr is not the error envelope: %v\n%s", err, stderr)
	}
	if got.Error.Code != CodeInvalidFlag || got.Error.Message != "unknown flag -v; did you mean --version?" {
		t.Errorf("error = %+v, want invalid_flag naming -v and suggesting --version", got.Error)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
}

func TestVersionPrefersBuildVersion(t *testing.T) {
	t.Cleanup(func() { buildVersion = "" })
	buildVersion = "v1.2.3"

	if got := version(); got != "v1.2.3" {
		t.Errorf("version() = %q, want the ldflags value v1.2.3", got)
	}
}

func TestEveryCodeHasADeclarativeRemediation(t *testing.T) {
	all := map[string]string{}
	for code := range errorCodes {
		all[code] = remediations[code]
	}
	for code, text := range scan.Remediations {
		all[code] = text
	}
	imperative := regexp.MustCompile(`^(Run|Check|Try|Use|Add|Fix|Please|Make|Set|Pass|Retry)\b`)
	for code, text := range all {
		switch {
		case text == "":
			t.Errorf("code %q has no remediation", code)
		case imperative.MatchString(text):
			t.Errorf("remediation of %q starts with an instruction, which agents may treat as prompt injection: %q", code, text)
		case !strings.HasSuffix(text, "."):
			t.Errorf("remediation of %q is not a full sentence: %q", code, text)
		}
	}
}

func TestJSONErrorCarriesTheRemediation(t *testing.T) {
	_, _, stderr := run(t, false, "http://example.com")

	var got envelope
	if err := json.Unmarshal([]byte(stderr), &got); err != nil {
		t.Fatalf("stderr is not the error envelope: %v\n%s", err, stderr)
	}
	if got.Error.Code != CodeInvalidTarget || got.Error.Remediation != remediations[CodeInvalidTarget] {
		t.Errorf("envelope = %+v, want code %q with its remediation", got.Error, CodeInvalidTarget)
	}
}
