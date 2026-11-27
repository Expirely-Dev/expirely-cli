package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/expirely-dev/expirely-cli/internal/acm"
)

func runInActions(t *testing.T, env map[string]string, client acm.API, args ...string) (code int, stdout, stderr, summary string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "summary.md")
	vars := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": path}
	for k, v := range env {
		vars[k] = v
	}
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"tls", "aws", "--region", "us-east-1"}, args...), Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errOut,
		Getenv: envOf(vars),
		NewACM: func(context.Context, string, string) (acm.Account, error) {
			return fakeAccount{region: "us-east-1", fallback: client}, nil
		},
	})
	written, err := os.ReadFile(filepath.Clean(path))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return code, out.String(), errOut.String(), string(written)
}

func TestGitHubActionsSummaryAndAnnotations(t *testing.T) {
	code, stdout, stderr, summary := runInActions(t, nil, sampleACM(), "--status", "expired")

	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("stdout = %q, want only the JSON report; annotations belong on stderr", stdout)
	}
	for _, want := range []string{
		"## expirely: 4 certificates need attention\n",
		"| unknown | `pending.example.com` |  |  | no end date: pending validation |",
		"| expired | `api.example.org` |",
		"| expiring | `api.example.com` |",
		"ACM us-east-1, in use by 2 resources",
		"Checked 6: 2 ok, 1 expiring, 2 expired, 0 unreadable, 1 unknown. warn-days 30,",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	if strings.Index(summary, "api.example.org") > strings.Index(summary, "api.example.com") {
		t.Errorf("summary = %s, want the most urgent certificate first", summary)
	}
	for _, want := range []string{
		"::error title=Certificate expired%3A api.example.org::api.example.org expired 770 days ago, on ",
		"::warning title=Certificate expiring%3A api.example.com::api.example.com expires in 12 days, on ",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestGitHubActionsSummaryWhenAllOK(t *testing.T) {
	notAfter := time.Now().Add(61*24*time.Hour + time.Hour)
	client := fakeACM{summaries: []types.CertificateSummary{
		{CertificateArn: aws.String("arn:1"), DomainName: aws.String("example.com"), Type: types.CertificateTypeAmazonIssued, Status: types.CertificateStatusIssued, RenewalEligibility: types.RenewalEligibilityEligible, NotAfter: &notAfter},
	}}

	code, _, stderr, summary := runInActions(t, nil, client)

	if code != ExitOK || stderr != "" {
		t.Errorf("exit code = %d, stderr = %q; want 0 and no annotations", code, stderr)
	}
	if !strings.HasPrefix(summary, "## expirely: the certificate is ok\n\n`example.com` expires first, in 61 days (") {
		t.Errorf("summary = %q, want the one certificate and when it expires", summary)
	}
}

func TestGitHubActionsOnlyInsideAWorkflow(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"outside GitHub Actions", map[string]string{"GITHUB_ACTIONS": ""}},
		{"turned off", map[string]string{"EXPIRELY_GITHUB": "0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, stderr, summary := runInActions(t, tt.env, sampleACM())

			if summary != "" || stderr != "" {
				t.Errorf("summary = %q, stderr = %q; want neither", summary, stderr)
			}
		})
	}
}

func TestGitHubActionsAnnotationsStopAtTheLimit(t *testing.T) {
	notAfter := time.Now().Add(5*24*time.Hour + time.Hour)
	var client fakeACM
	for i := range 12 {
		client.summaries = append(client.summaries, types.CertificateSummary{
			CertificateArn: aws.String(fmt.Sprintf("arn:%d", i)), DomainName: aws.String(fmt.Sprintf("host%02d.example.com", i)),
			Type: types.CertificateTypeAmazonIssued, Status: types.CertificateStatusIssued, NotAfter: &notAfter,
		})
	}

	_, _, stderr, _ := runInActions(t, nil, client)

	if n := strings.Count(stderr, "::warning "); n != maxAnnotations {
		t.Errorf("warnings = %d, want %d", n, maxAnnotations)
	}
	if !strings.Contains(stderr, "::notice title=expirely::2 more certificates need attention") {
		t.Errorf("stderr = %s, want a notice counting the 2 not shown", stderr)
	}
}

func TestGitHubTextCannotBreakOut(t *testing.T) {
	if got := markdownCell("a|b <script>\nc"); got != `a\|b &lt;script&gt; c` {
		t.Errorf("markdownCell = %q", got)
	}
	if got := workflowData("50% done\r\n::error::x"); strings.ContainsAny(got, "\r\n") || !strings.HasPrefix(got, "50%25 done") {
		t.Errorf("workflowData = %q, want one line with %% escaped", got)
	}
	if got := workflowProperty("Not read: acm:us-east-1, acm:eu-west-1"); got != "Not read%3A acm%3Aus-east-1%2C acm%3Aeu-west-1" {
		t.Errorf("workflowProperty = %q", got)
	}
}
