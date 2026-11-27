package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/gcp"
	"github.com/expirely-dev/expirely-cli/internal/gcp/gcptest"
	"github.com/expirely-dev/expirely-cli/internal/scan"
	"github.com/expirely-dev/expirely-cli/internal/tlstest"
)

type viewReport struct {
	Summary map[string]int `json:"summary"`
	Filter  struct {
		Status []string `json:"status"`
		Limit  *int     `json:"limit"`
	} `json:"filter"`
	Matched   int                          `json:"matched"`
	Truncated bool                         `json:"truncated"`
	Results   []map[string]json.RawMessage `json:"results"`
}

func runAgent(t *testing.T, terminal bool, env map[string]string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	Run(context.Background(), args, Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
		Getenv:           envOf(env),
	})
	return out.String()
}

func decodeView(t *testing.T, stdout string) viewReport {
	t.Helper()
	var r viewReport
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\n%s", err, stdout)
	}
	return r
}

func targetsOf(r viewReport) []string {
	var out []string
	for _, res := range r.Results {
		var target string
		_ = json.Unmarshal(res["target"], &target)
		out = append(out, target)
	}
	return out
}

// threeTargets serves one healthy, one expiring and one expired
// certificate and returns their targets in that order.
func threeTargets(t *testing.T) []string {
	t.Helper()
	ca := tlstest.NewCA(t)
	day := 24 * time.Hour
	var targets []string
	for _, end := range []time.Duration{90 * day, 5*day + time.Hour, -time.Hour} {
		port := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(end)))
		targets = append(targets, fmt.Sprintf("localhost:%d", port))
	}
	return targets
}

func TestStatusFiltersResultsButNotTheSummaryOrTheExitCode(t *testing.T) {
	targets := threeTargets(t)
	healthy, expiring, expired := targets[0], targets[1], targets[2]

	code, stdout, stderr := run(t, false, append([]string{"--status", "ok"}, targets...)...)

	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d: the expired certificate still fails, hidden or not; stderr = %s", code, ExitFindings, stderr)
	}
	r := decodeView(t, stdout)
	if got := targetsOf(r); !slices.Equal(got, []string{healthy}) {
		t.Errorf("results = %v, want only %s", got, healthy)
	}
	if r.Summary["total"] != 3 || r.Summary["expired"] != 1 || r.Summary["expiring"] != 1 || r.Summary["ok"] != 1 {
		t.Errorf("summary = %v, want every result counted", r.Summary)
	}
	if r.Matched != 1 || r.Truncated || !slices.Equal(r.Filter.Status, []string{"ok"}) || r.Filter.Limit != nil {
		t.Errorf("matched = %d, truncated = %v, filter = %+v; want 1, false, [ok] and no limit", r.Matched, r.Truncated, r.Filter)
	}

	_, stdout, _ = run(t, false, append([]string{"--status", "ok,expired", "--status", "expiring"}, targets...)...)
	if got := targetsOf(decodeView(t, stdout)); !slices.Equal(got, []string{expired, expiring, healthy}) {
		t.Errorf("results with a repeated, comma-separated --status = %v, want all three, most urgent first", got)
	}
}

func TestLimitKeepsTheMostUrgentAndSaysSo(t *testing.T) {
	targets := threeTargets(t)

	code, stdout, _ := run(t, false, append([]string{"--limit", "2"}, targets...)...)

	r := decodeView(t, stdout)
	if got := targetsOf(r); !slices.Equal(got, []string{targets[2], targets[1]}) {
		t.Errorf("results = %v, want the expired then the expiring certificate", got)
	}
	if r.Matched != 3 || !r.Truncated || r.Filter.Limit == nil || *r.Filter.Limit != 2 {
		t.Errorf("matched = %d, truncated = %v, limit = %v; want 3, true, 2", r.Matched, r.Truncated, r.Filter.Limit)
	}
	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}

	_, stdout, _ = run(t, false, append([]string{"--limit", "3"}, targets...)...)
	if r := decodeView(t, stdout); r.Truncated || len(r.Results) != 3 {
		t.Errorf("a limit as large as the results gives truncated = %v and %d results, want false and 3", r.Truncated, len(r.Results))
	}
}

func TestCountsComeBeforeTheResults(t *testing.T) {
	_, stdout, _ := run(t, false, threeTargets(t)...)

	keys := []string{`"schema_version"`, `"summary"`, `"filter"`, `"matched"`, `"truncated"`, `"unreadable"`, `"results"`}
	last := -1
	for _, k := range keys {
		i := strings.Index(stdout, k)
		if i < last {
			t.Fatalf("%s comes before an earlier key in %s; a reader that sees only the start of the output needs the counts", k, stdout)
		}
		last = i
	}
	if !strings.Contains(stdout, `"truncated":false`) || !strings.Contains(stdout, `"limit":null`) {
		t.Errorf("stdout = %s, want truncated and limit present without --limit", stdout)
	}
	if !strings.Contains(stdout, `"unreadable":[]`) {
		t.Errorf("stdout = %s, want unreadable present and empty for a complete report", stdout)
	}
}

func TestFieldsProjectEachResult(t *testing.T) {
	targets := threeTargets(t)

	_, stdout, stderr := run(t, false, append([]string{"--fields", "days_left,status", "--fields", "acm", "--limit", "1"}, targets...)...)

	if stderr != "" {
		t.Fatalf("stderr = %s, want empty", stderr)
	}
	start := strings.Index(stdout, `"results":[`) + len(`"results":[`)
	want := fmt.Sprintf(`{"target":%q,"status":"expired","days_left":-1,"acm":null}`, targets[2])
	if got := stdout[start : start+len(want)]; got != want {
		t.Errorf("result = %s, want %s: target always, schema order, null for a field with no value", got, want)
	}
	if !strings.Contains(stdout, `"summary":{`) {
		t.Errorf("stdout = %s, want the summary kept", stdout)
	}

	_, stdout, _ = run(t, false, append([]string{"--fields", "chain"}, targets[0])...)
	if r := decodeView(t, stdout); len(r.Results) != 1 || string(r.Results[0]["chain"]) == "null" {
		t.Errorf("--fields chain = %s, want the chain without --details", stdout)
	}
}

func TestViewFlagsAreCheckedBeforeAnyScan(t *testing.T) {
	closed := fmt.Sprintf("localhost:%d", tlstest.ClosedPort(t))
	tests := []struct {
		name     string
		terminal bool
		args     []string
		wantMsg  string
	}{
		{name: "unknown status", args: []string{"--status", "expired,stale"}, wantMsg: `unknown status "stale" in --status; valid: expired, expiring, error, ok, all`},
		{name: "unknown field", args: []string{"--fields", "target,days"}, wantMsg: `unknown field "days" in --fields; valid: target, status, days_left`},
		{name: "zero limit", args: []string{"--limit", "0"}, wantMsg: "--limit must be 1 or more, got 0"},
		{name: "negative limit", args: []string{"--limit", "-3"}, wantMsg: "--limit must be 1 or more, got -3"},
		{name: "fields on text", terminal: true, args: []string{"--fields", "status"}, wantMsg: "--fields selects JSON fields, and this run prints text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.terminal, append(tt.args, closed)...)

			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d before scanning %s", code, ExitUsage, closed)
			}
			msg := stderr
			if !tt.terminal {
				var env envelope
				if err := json.Unmarshal([]byte(stderr), &env); err != nil || env.Error.Code != CodeInvalidFlag {
					t.Fatalf("stderr = %s, want the %q envelope", stderr, CodeInvalidFlag)
				}
				msg = env.Error.Message
			}
			if stdout != "" || !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("stdout = %q, message = %q; want only an error containing %q", stdout, msg, tt.wantMsg)
			}
		})
	}
}

func TestDeclaredAgentsSeeWhatNeedsAttention(t *testing.T) {
	targets := threeTargets(t)
	agentEnv := map[string]string{"AI_AGENT": "claude-code"}

	stdout := runAgent(t, true, agentEnv, targets...)

	r := decodeView(t, stdout)
	if got := targetsOf(r); !slices.Equal(got, []string{targets[2], targets[1]}) {
		t.Errorf("results = %v, want the expired and expiring certificates and no ok one", got)
	}
	if !slices.Equal(r.Filter.Status, []string{"expired", "expiring", "error"}) || r.Summary["ok"] != 1 || r.Summary["total"] != 3 {
		t.Errorf("filter = %v, summary = %v; want the default agent statuses and every result counted", r.Filter.Status, r.Summary)
	}

	stdout = runAgent(t, true, agentEnv, append([]string{"--status", "all"}, targets...)...)
	if r := decodeView(t, stdout); len(r.Results) != 3 {
		t.Errorf("--status all gives %d results, want 3", len(r.Results))
	}

	stdout = runAgent(t, false, map[string]string{"CLAUDECODE": "1"}, targets...)
	if r := decodeView(t, stdout); len(r.Results) != 3 {
		t.Errorf("an agent that does not declare itself gets %d results, want all 3", len(r.Results))
	}
}

func TestTextSaysWhatIsHidden(t *testing.T) {
	targets := threeTargets(t)

	_, stdout, _ := run(t, true, append([]string{"--status", "expired,expiring", "--limit", "1"}, targets...)...)

	if strings.Contains(stdout, "expiring  ") || !strings.Contains(stdout, "expired  ") {
		t.Errorf("stdout = %q, want only the expired row", stdout)
	}
	if !strings.Contains(stdout, "showing 1 of 3 (--status expired,expiring; --limit 1)") {
		t.Errorf("stdout = %q, want a line saying what is hidden and why", stdout)
	}

	_, stdout, _ = run(t, true, targets...)
	if strings.Contains(stdout, "showing") {
		t.Errorf("stdout = %q, want no hidden note when every result shows", stdout)
	}
}

func TestViewFlagsWorkOnCloudCommands(t *testing.T) {
	endpoint := gcptest.Serve(t, "acme-prod", gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})
	var out, errOut bytes.Buffer

	code := Run(context.Background(), []string{"gcp", "--project", "acme-prod", "--status", "expiring", "--limit", "1", "--fields", "gcp"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errOut,
		NewGCP: func(context.Context) (*gcp.Service, error) {
			return &gcp.Service{Client: http.DefaultClient, ComputeEndpoint: endpoint.Compute, CertificateManagerEndpoint: endpoint.CertificateManager}, nil
		},
	})

	r := decodeView(t, out.String())
	if code != ExitFindings || len(r.Results) != 1 || !r.Truncated || len(r.Results[0]) != 2 {
		t.Errorf("exit code = %d, report = %s, stderr = %s; want one projected expiring result, truncated", code, out.String(), errOut.String())
	}
}

func TestResultFieldsMatchTheFindingJSON(t *testing.T) {
	var tags []string
	ft := reflect.TypeFor[scan.Finding]()
	for i := range ft.NumField() {
		tags = append(tags, strings.Split(ft.Field(i).Tag.Get("json"), ",")[0])
	}
	if !slices.Equal(tags, resultFields) {
		t.Errorf("scan.Finding JSON keys = %v, resultFields = %v; --fields must accept exactly the keys a result prints", tags, resultFields)
	}
}

func TestFlagsAfterTargets(t *testing.T) {
	targets := threeTargets(t)

	code, stdout, stderr := run(t, false, targets[0], "--status", "ok", targets[1], "--fields=status", targets[2])

	r := decodeView(t, stdout)
	if code != ExitFindings || stderr != "" || r.Summary["total"] != 3 || !slices.Equal(r.Filter.Status, []string{"ok"}) || len(r.Results[0]) != 2 {
		t.Errorf("exit code = %d, stderr = %s, report = %s; want flags read wherever they are among the targets", code, stderr, stdout)
	}

	code, _, stderr = run(t, false, targets[0], "--", "--status")
	var env envelope
	if code != ExitUsage || json.Unmarshal([]byte(stderr), &env) != nil || env.Error.Code != CodeInvalidTarget || !strings.Contains(env.Error.Message, `"--status"`) {
		t.Errorf("exit code = %d, stderr = %s; want everything after -- read as a target", code, stderr)
	}
}
