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

	"github.com/expirely-dev/expirely-cli/internal/tls/gcp"
	"github.com/expirely-dev/expirely-cli/internal/tls/gcp/gcptest"
)

func runGCPWith(t *testing.T, terminal bool, f gcptest.Fake, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	endpoint := gcptest.Serve(t, "acme-prod", f)
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"tls", "gcp"}, args...), Streams{
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
	if !strings.Contains(stdout, "unknown") || !strings.Contains(stdout, "new.example.com") || !strings.Contains(stdout, "provisioning") {
		t.Errorf("stdout = %q, want the managed certificate not issued yet as unknown, provisioning", stdout)
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
	if len(got.Results) != 6 {
		t.Fatalf("len(results) = %d, want 6: five issued certificates and one provisioning", len(got.Results))
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
	if sources["compute"] != 4 || sources["certificate_manager"] != 2 {
		t.Errorf("sources = %v, want 4 compute, one of them provisioning, and 2 certificate_manager", sources)
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
	code := Run(context.Background(), []string{"tls", "gcp", "--project", "acme-prod"}, Streams{
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

func oneGCPCert(expires time.Time, unreachable ...string) gcptest.Fake {
	sslCertificates := map[string]any{
		"items": map[string]any{"global": map[string]any{"sslCertificates": []any{
			map[string]any{"name": "api-cert", "type": "SELF_MANAGED", "subjectAlternativeNames": []string{"api.example.com"}, "expireTime": expires.UTC().Format(time.RFC3339)},
		}}},
	}
	if len(unreachable) > 0 {
		sslCertificates["unreachables"] = unreachable
	}
	return gcptest.Fake{Bodies: map[string]any{
		"aggregated/sslCertificates":    sslCertificates,
		"aggregated/targetHttpsProxies": nil,
		"global/targetSslProxies":       nil,
		"locations":                     nil,
	}}
}

func TestGCPReportsWhatItCouldNotRead(t *testing.T) {
	inAYear := time.Now().AddDate(1, 0, 0)
	t.Run("json", func(t *testing.T) {
		code, stdout, stderr := runGCPWith(t, false, oneGCPCert(inAYear, "regions/us-east7"), nil, "--project", "acme-prod")

		var got struct {
			Unreadable []string          `json:"unreadable"`
			Results    []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("stdout is not the JSON report: %v\nstderr: %s", err, stderr)
		}
		if len(got.Unreadable) != 1 || got.Unreadable[0] != "compute:us-east7" || len(got.Results) != 1 {
			t.Errorf("unreadable = %v with %d results, want compute:us-east7 and the certificate read", got.Unreadable, len(got.Results))
		}
		if code != ExitFailure {
			t.Errorf("exit code = %d, want %d: the certificate read is ok, but the report is incomplete", code, ExitFailure)
		}
	})
	t.Run("text", func(t *testing.T) {
		code, stdout, stderr := runGCPWith(t, true, oneGCPCert(inAYear, "regions/us-east7"), nil, "--project", "acme-prod")

		if !strings.Contains(stderr, "could not read compute:us-east7") {
			t.Errorf("stderr = %q, want the place it could not read", stderr)
		}
		if !strings.Contains(stdout, "api.example.com") || code != ExitFailure {
			t.Errorf("exit code = %d, stdout = %q; want the certificate read and exit %d", code, stdout, ExitFailure)
		}
	})
	t.Run("findings still exit 1", func(t *testing.T) {
		code, _, stderr := runGCPWith(t, false, oneGCPCert(time.Now().AddDate(0, 0, 5), "regions/us-east7"), nil, "--project", "acme-prod")

		if code != ExitFindings {
			t.Errorf("exit code = %d, want %d for an expiring certificate even with a region unread; stderr = %s", code, ExitFindings, stderr)
		}
	})
	t.Run("complete report exits 0", func(t *testing.T) {
		code, stdout, stderr := runGCPWith(t, false, oneGCPCert(inAYear), nil, "--project", "acme-prod")

		if code != ExitOK || !strings.Contains(stdout, `"unreadable":[]`) {
			t.Errorf("exit code = %d, stdout = %s, stderr = %s; want 0 and an empty unreadable", code, stdout, stderr)
		}
	})
}
