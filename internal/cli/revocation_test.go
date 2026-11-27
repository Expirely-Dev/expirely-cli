package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
	"github.com/expirely-dev/expirely-cli/internal/tls/tlstest"
)

// revokedTarget serves a certificate its CA revoked and returns the target,
// a --ca-file that trusts that CA, and the count of requests for the CRL.
func revokedTarget(t *testing.T) (target, caFile string, fetches *atomic.Int32) {
	t.Helper()
	ca := tlstest.NewCA(t)
	crl := ca.CRL(t, time.Now().Add(24*time.Hour), 7)
	fetches = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write(crl)
	}))
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	target = fmt.Sprintf("localhost:%d", tlstest.ServeTLS(t, ca.RevocableLeaf(t, "localhost", 7, srv.URL+"/crl")))
	return target, caFile, fetches
}

func TestRevocation(t *testing.T) {
	const untrusted = `{"status":"unknown","reason":"the chain is not trusted, so the CRL its certificate names was not fetched"}`
	tests := []struct {
		name        string
		args        []string
		trust       bool
		wantCode    int
		wantStatus  string
		wantRevoc   string
		wantFetches int32
	}{
		{name: "not checked without --revocation", trust: true, wantCode: ExitOK, wantStatus: "ok", wantRevoc: "null"},
		{name: "a revoked certificate is revoked and fails the run", args: []string{"--revocation"}, trust: true, wantCode: ExitFindings, wantStatus: "revoked", wantRevoc: `{"status":"revoked","reason":"revoked on 2026-11-01T00:00:00Z"}`, wantFetches: 1},
		{name: "an untrusted chain never has its CRL fetched", args: []string{"--revocation"}, wantCode: ExitOK, wantStatus: "ok", wantRevoc: untrusted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, caFile, fetches := revokedTarget(t)
			args := append([]string{"--warn-days", "7"}, tt.args...)
			if tt.trust {
				args = append(args, "--ca-file", caFile)
			}

			code, stdout, stderr := run(t, false, append(args, target)...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d; stderr = %s", code, tt.wantCode, stderr)
			}
			var got struct {
				Summary map[string]int `json:"summary"`
				Results []struct {
					Status string `json:"status"`
					TLS    struct {
						Revocation json.RawMessage `json:"revocation"`
					} `json:"tls"`
				} `json:"results"`
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil || len(got.Results) != 1 {
				t.Fatalf("stdout = %s, want one result: %v", stdout, err)
			}
			if r := got.Results[0]; r.Status != tt.wantStatus || string(r.TLS.Revocation) != tt.wantRevoc {
				t.Errorf("status = %q, tls.revocation = %s; want %q and %s", r.Status, r.TLS.Revocation, tt.wantStatus, tt.wantRevoc)
			}
			if got.Summary[tt.wantStatus] != 1 {
				t.Errorf("summary = %v, want 1 %s", got.Summary, tt.wantStatus)
			}
			if n := fetches.Load(); n != tt.wantFetches {
				t.Errorf("CRL requests = %d, want %d", n, tt.wantFetches)
			}
		})
	}
}

func TestRevokedIsShownToADeclaredAgent(t *testing.T) {
	target, caFile, _ := revokedTarget(t)

	stdout := runAgent(t, true, map[string]string{"AI_AGENT": "claude-code"}, "--warn-days", "7", "--revocation", "--ca-file", caFile, target)

	if r := decodeView(t, stdout); len(r.Results) != 1 {
		t.Errorf("stdout = %s, want the revoked certificate among what a declared agent sees by default", stdout)
	}
}

func TestRevokedInText(t *testing.T) {
	target, caFile, _ := revokedTarget(t)

	code, stdout, _ := run(t, true, "--warn-days", "7", "--revocation", "--ca-file", caFile, target)

	if code != ExitFindings || !strings.Contains(stdout, "  revoked  localhost:") || !strings.Contains(stdout, "1 revoked in ") {
		t.Errorf("exit = %d, stdout = %q; want exit 1, a revoked line and 1 revoked in the summary", code, stdout)
	}
}

func TestRevokedInGitHubActions(t *testing.T) {
	f := scan.Finding{Target: "api.example.com:443", Status: scan.StatusRevoked, DaysLeft: ptr(40), ExpiresAt: ptr(time.Date(2027, 1, 6, 0, 0, 0, 0, time.UTC))}
	r := newReport(time.Now(), 30, []scan.Finding{f}, nil)

	if summary := githubSummary(r, []scan.Finding{f}); !strings.Contains(summary, "1 certificate needs attention") || !strings.Contains(summary, "| revoked | `api.example.com` | Jan 06 2027 | 40 |") || !strings.Contains(summary, "0 expired, 1 revoked, 0 unreadable") {
		t.Errorf("summary = %s, want the revoked certificate listed and counted", summary)
	}
	var b bytes.Buffer
	writeAnnotations(&b, r, []scan.Finding{f})
	if want := "::error title=Certificate revoked%3A api.example.com::api.example.com is revoked; it would expire in 40 days, on Jan 06 2027.\n"; b.String() != want {
		t.Errorf("annotations = %q, want %q", b.String(), want)
	}
}

func TestNotesSayWhenRenewalIsNotWorking(t *testing.T) {
	tests := []struct {
		name     string
		finding  scan.Finding
		want     string
		wantWarn bool
	}{
		{name: "ACM renews", finding: scan.Finding{ACM: &scan.ACMInfo{RenewalEligibility: "ELIGIBLE", RenewalStatus: ptr("PENDING_AUTO_RENEWAL")}}, want: "renews itself"},
		{name: "ACM renewal failed", finding: scan.Finding{ACM: &scan.ACMInfo{RenewalEligibility: "ELIGIBLE", RenewalStatus: ptr("FAILED"), InUseBy: []string{"lb"}}}, want: "renewal failed, in use by 1 resource", wantWarn: true},
		{name: "ACM renewal waits for validation", finding: scan.Finding{ACM: &scan.ACMInfo{RenewalEligibility: "ELIGIBLE", RenewalStatus: ptr("PENDING_VALIDATION"), InUseBy: []string{"lb"}}}, want: "renewal waits for validation, in use by 1 resource", wantWarn: true},
		{name: "Google renews", finding: scan.Finding{GCP: &scan.GCPInfo{Managed: true, State: ptr("ACTIVE")}}, want: "renews itself"},
		{name: "Google renewal failed", finding: scan.Finding{GCP: &scan.GCPInfo{Managed: true, State: ptr("RENEWAL_FAILED")}}, want: "renewal failed", wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, warn := note(tt.finding); got != tt.want || warn != tt.wantWarn {
				t.Errorf("note() = %q, %v; want %q, %v", got, warn, tt.want, tt.wantWarn)
			}
		})
	}
}
