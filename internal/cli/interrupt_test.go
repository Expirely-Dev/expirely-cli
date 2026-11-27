package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/expirely-dev/expirely-cli/internal/tls/acm"
	"github.com/expirely-dev/expirely-cli/internal/tls/gcp"
	"github.com/expirely-dev/expirely-cli/internal/tls/gcp/gcptest"
)

func TestRunStopsWhenInterrupted(t *testing.T) {
	endpoint := gcptest.Serve(t, "acme-prod", gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})
	tests := []struct {
		name string
		args []string
	}{
		{name: "scan", args: []string{"tls", "example.com", "example.org"}},
		{name: "aws", args: []string{"tls", "aws", "--region", "us-east-1"}},
		{name: "gcp", args: []string{"tls", "gcp", "--project", "acme-prod"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var out, errOut bytes.Buffer

			code := Run(ctx, tt.args, Streams{
				Stdin:  strings.NewReader(""),
				Stdout: &out,
				Stderr: &errOut,
				NewACM: func(context.Context, string, string) (acm.Account, error) {
					return fakeAccount{region: "us-east-1", fallback: sampleACM()}, nil
				},
				NewGCP: func(context.Context) (*gcp.Service, error) {
					return &gcp.Service{Client: http.DefaultClient, ComputeEndpoint: endpoint.Compute, CertificateManagerEndpoint: endpoint.CertificateManager}, nil
				},
			})

			if code != ExitInterrupted {
				t.Errorf("exit code = %d, want %d", code, ExitInterrupted)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want no partial results", out.String())
			}
			var env envelope
			if err := json.Unmarshal(errOut.Bytes(), &env); err != nil || env.Error.Code != CodeInterrupted {
				t.Errorf("stderr = %s, want the %q envelope", errOut.String(), CodeInterrupted)
			}
		})
	}
}
