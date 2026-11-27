package cli

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/expirely-dev/expirely-cli/internal/acm"
	"github.com/expirely-dev/expirely-cli/internal/gcp"
	"github.com/expirely-dev/expirely-cli/internal/gcp/gcptest"
)

const slowRead = 300 * time.Millisecond

type slowACM struct{ fakeACM }

func (s slowACM) ListCertificates(ctx context.Context, in *sdk.ListCertificatesInput, opts ...func(*sdk.Options)) (*sdk.ListCertificatesOutput, error) {
	time.Sleep(slowRead)
	return s.fakeACM.ListCertificates(ctx, in, opts...)
}

type slowTransport struct{ first sync.Once }

func (s *slowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.first.Do(func() { time.Sleep(slowRead) })
	return http.DefaultTransport.RoundTrip(r)
}

func TestCloudCommandsShowProgressOnlyToAPersonAtATerminal(t *testing.T) {
	endpoint := gcptest.Serve(t, "acme-prod", gcptest.Fake{Bodies: gcptest.Sample("acme-prod")})
	commands := []struct {
		name  string
		args  []string
		label string
	}{
		{"aws", []string{"tls", "aws", "--region", "us-east-1"}, "Reading ACM in us-east-1"},
		{"gcp", []string{"tls", "gcp", "--project", "acme-prod"}, "Reading the certificates of project acme-prod"},
	}
	readers := []struct {
		name     string
		terminal bool
		env      map[string]string
		want     bool
	}{
		{"person at a terminal", true, nil, true},
		{"stderr not a terminal", false, nil, false},
		{"agent at a terminal", true, map[string]string{"GEMINI_CLI": "1"}, false},
	}
	for _, cmd := range commands {
		for _, r := range readers {
			t.Run(cmd.name+"/"+r.name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), cmd.args, Streams{
					Stdin:            strings.NewReader(""),
					Stdout:           &stdout,
					Stderr:           &stderr,
					StdoutIsTerminal: true,
					StderrIsTerminal: r.terminal,
					Getenv:           envOf(r.env),
					NewACM: func(context.Context, string, string) (acm.Account, error) {
						return fakeAccount{region: "us-east-1", fallback: slowACM{sampleACM()}}, nil
					},
					NewGCP: func(context.Context) (*gcp.Service, error) {
						return &gcp.Service{Client: &http.Client{Transport: &slowTransport{}}, ComputeEndpoint: endpoint.Compute, CertificateManagerEndpoint: endpoint.CertificateManager}, nil
					},
				})
				if code == ExitUsage || code == ExitFailure {
					t.Fatalf("exit code = %d; stderr = %s", code, stderr.String())
				}

				got := stderr.String()
				switch {
				case r.want && !strings.Contains(got, cmd.label):
					t.Errorf("stderr = %q, want the spinner labeled %q", got, cmd.label)
				case r.want && !strings.HasSuffix(got, "\r\x1b[2K"):
					t.Errorf("stderr = %q, want the spinner line erased at the end", got)
				case !r.want && got != "":
					t.Errorf("stderr = %q, want nothing", got)
				}
				if strings.Contains(stdout.String(), cmd.label) {
					t.Errorf("stdout = %q, want the spinner kept off stdout", stdout.String())
				}
			})
		}
	}
}
