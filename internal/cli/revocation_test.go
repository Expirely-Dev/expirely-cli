package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/scan"
	"github.com/expirely-dev/expirely-cli/internal/tlstest"
)

func revokedTarget(t *testing.T) string {
	t.Helper()
	ca := tlstest.NewCA(t)
	crl := ca.CRL(t, time.Now().Add(24*time.Hour), 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(crl) }))
	t.Cleanup(srv.Close)
	return fmt.Sprintf("localhost:%d", tlstest.ServeTLS(t, ca.RevocableLeaf(t, "localhost", 7, srv.URL+"/crl")))
}

func TestRevocationIsCheckedOnlyOnRequest(t *testing.T) {
	target := revokedTarget(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "without --revocation", args: []string{"--warn-days", "7", target}, want: "null"},
		{name: "with --revocation", args: []string{"--warn-days", "7", "--revocation", target}, want: `{"status":"revoked","reason":"revoked on 2026-11-01T00:00:00Z"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, false, tt.args...)

			if code != ExitOK {
				t.Errorf("exit code = %d, want %d: revocation does not change the exit code; stderr = %s", code, ExitOK, stderr)
			}
			var got struct {
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
			if r := got.Results[0]; r.Status != "ok" || string(r.TLS.Revocation) != tt.want {
				t.Errorf("status = %q, tls.revocation = %s; want ok and %s", r.Status, r.TLS.Revocation, tt.want)
			}
		})
	}
}

func TestRevokedIsANoteInText(t *testing.T) {
	_, stdout, _ := run(t, true, "--warn-days", "7", "--revocation", revokedTarget(t))

	if !strings.Contains(stdout, "ok ") || !strings.Contains(stdout, "revoked") {
		t.Errorf("stdout = %q, want an ok line with the note revoked", stdout)
	}
}

func TestRevokedNeedsAttentionInGitHubActions(t *testing.T) {
	reason := "revoked on 2026-11-01T00:00:00Z"
	f := scan.Finding{Target: "api.example.com:443", Status: scan.StatusOK, DaysLeft: ptr(40), ExpiresAt: ptr(time.Date(2027, 1, 6, 0, 0, 0, 0, time.UTC)),
		TLS: scan.TLSInfo{Revocation: &scan.Revocation{Status: "revoked", Reason: &reason}}}
	r := newReport(time.Now(), 30, []scan.Finding{f}, nil)

	if summary := githubSummary(r, []scan.Finding{f}); !strings.Contains(summary, "1 certificate needs attention") || !strings.Contains(summary, "| ok | `api.example.com` | Jan 06 2027 | 40 | revoked |") {
		t.Errorf("summary = %s, want the revoked certificate listed", summary)
	}
	var b bytes.Buffer
	writeAnnotations(&b, r, []scan.Finding{f})
	if want := "::error title=Certificate revoked%3A api.example.com::api.example.com is revoked by its CA; it expires in 40 days, on Jan 06 2027.\n"; b.String() != want {
		t.Errorf("annotations = %q, want %q", b.String(), want)
	}
}
