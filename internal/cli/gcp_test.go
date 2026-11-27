package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/gcp"
	"github.com/bycavii/expirely-cli/internal/gcp/gcptest"
	"github.com/bycavii/expirely-cli/internal/scan"
)

func runGCPWith(t *testing.T, terminal bool, f gcptest.Fake, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	endpoint := gcptest.Serve(t, "acme-prod", f)
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"gcp"}, args...), Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
		Getenv:           envOf(env),
		NewGCP: func(context.Context) (*gcp.Service, error) {
			return &gcp.Service{Client: http.DefaultClient, ComputeEndpoint: endpoint.Compute, CertificateManagerEndpoint: endpoint.CertificateManager}, nil
		},
	})
	return code, out.String(), errOut.String()
}

func TestGCPText(t *testing.T) {
	code, stdout, stderr := runGCPWith(t, true, gcptest.Fake{Bodies: gcptest.Sample("acme-prod")}, nil, "--project", "acme-prod")

	if code != ExitFindings && code != ExitOK {
		t.Fatalf("exit code = %d; stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"api.example.com",
		"self-managed, in use by 2 resources",
		"www.example.com",
		"renews itself",
		"internal.example.com",
		"self-managed, in use by 1 resource",
		"shop.example.com",
		"legacy.example.com",
		"self-managed, not in use",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout, want)
		}
	}
	if strings.Contains(stdout, "new.example.com") {
		t.Errorf("stdout lists a managed certificate not issued yet:\n%s", stdout)
	}
}

func TestGCPJSONAndProjectFromEnvironment(t *testing.T) {
	_, stdout, stderr := runGCPWith(t, false, gcptest.Fake{Bodies: gcptest.Sample("acme-prod")}, map[string]string{"GOOGLE_CLOUD_PROJECT": "acme-prod"})

	var got struct {
		Results []struct {
			Target string          `json:"target"`
			GCP    json.RawMessage `json:"gcp"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\nstderr: %s", err, stderr)
	}
	if len(got.Results) != 5 {
		t.Fatalf("len(results) = %d, want 5 issued certificates", len(got.Results))
	}
	sources := map[string]int{}
	for _, r := range got.Results {
		var info struct {
			Source string `json:"source"`
		}
		if err := json.Unmarshal(r.GCP, &info); err != nil || info.Source == "" {
			t.Errorf("result %s has gcp %s, want an object with its source", r.Target, r.GCP)
		}
		sources[info.Source]++
	}
	if sources["compute"] != 3 || sources["certificate_manager"] != 2 {
		t.Errorf("sources = %v, want 3 compute and 2 certificate_manager", sources)
	}
}

func TestGCPErrors(t *testing.T) {
	tests := []struct {
		name     string
		f        gcptest.Fake
		env      map[string]string
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "no project", f: gcptest.Fake{Bodies: gcptest.Sample("acme-prod")}, wantCode: ExitUsage, wantErr: CodeGCPNotConfigured},
		{name: "permission denied", f: gcptest.Fake{Status: http.StatusForbidden, Reason: "IAM_PERMISSION_DENIED"}, args: []string{"--project", "acme-prod"}, wantCode: ExitFailure, wantErr: CodeGCPAccessDenied},
		{name: "compute api disabled", f: gcptest.Fake{Status: http.StatusForbidden, Reason: "SERVICE_DISABLED"}, args: []string{"--project", "acme-prod"}, wantCode: ExitFailure, wantErr: CodeGCPComputeDisabled},
		{name: "billing disabled", f: gcptest.Fake{Status: http.StatusForbidden, Reason: "BILLING_DISABLED"}, args: []string{"--project", "acme-prod"}, wantCode: ExitFailure, wantErr: CodeGCPComputeDisabled},
		{name: "server error", f: gcptest.Fake{Status: http.StatusInternalServerError}, args: []string{"--project", "acme-prod", "--timeout", "2s"}, wantCode: ExitFailure, wantErr: CodeGCPRequestFailed},
		{name: "targets are not accepted", f: gcptest.Fake{}, args: []string{"--project", "acme-prod", "example.com"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runGCPWith(t, false, tt.f, tt.env, tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			var env envelope
			if err := json.Unmarshal([]byte(stderr), &env); err != nil || env.Error.Code != tt.wantErr {
				t.Errorf("stderr = %s, want the %q envelope", stderr, tt.wantErr)
			}
		})
	}
}

func TestGCPClientError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"gcp", "--project", "acme-prod"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errOut,
		NewGCP: func(context.Context) (*gcp.Service, error) {
			return nil, errors.New("google: could not find default credentials")
		},
	})

	var env envelope
	if code != ExitUsage || json.Unmarshal(errOut.Bytes(), &env) != nil || env.Error.Code != CodeGCPNotConfigured {
		t.Errorf("exit code = %d, stderr = %s; want %d and %q", code, errOut.String(), ExitUsage, CodeGCPNotConfigured)
	}
}

func TestGCPFindings(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	soon := now.Add(12 * day)
	certs := []gcp.Certificate{
		{Name: "api-cert", Domain: "api.example.com", Location: "global", NotAfter: &soon},
		{Name: "pending", Domain: "new.example.com", Location: "global", Managed: true},
	}

	got := gcpFindings(certs, now, 30*day)

	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1; a certificate not issued yet has no end date", len(got))
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != scan.StatusExpiring || f.GCP.Managed || f.GCP.InUseBy == nil || f.Trusted != nil {
		t.Errorf("findings[0] = %+v, gcp = %+v; want an expiring self-managed certificate, an empty in_use_by and no trust fields", f, f.GCP)
	}
}
