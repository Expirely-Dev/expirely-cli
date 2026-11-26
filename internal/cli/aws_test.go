package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/smithy-go"
	"github.com/bycavii/expirely-cli/internal/acm"
)

type fakeACM struct {
	summaries []types.CertificateSummary
	inUseBy   map[string][]string
	listErr   error
}

func (f fakeACM) ListCertificates(context.Context, *sdk.ListCertificatesInput, ...func(*sdk.Options)) (*sdk.ListCertificatesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &sdk.ListCertificatesOutput{CertificateSummaryList: f.summaries}, nil
}

func (f fakeACM) DescribeCertificate(_ context.Context, in *sdk.DescribeCertificateInput, _ ...func(*sdk.Options)) (*sdk.DescribeCertificateOutput, error) {
	return &sdk.DescribeCertificateOutput{Certificate: &types.CertificateDetail{InUseBy: f.inUseBy[aws.ToString(in.CertificateArn)]}}, nil
}

func sampleACM() fakeACM {
	at := func(days int) *time.Time {
		t := time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour)
		return &t
	}
	cert := func(arn, domain string, typ types.CertificateType, renewal types.RenewalEligibility, notAfter *time.Time) types.CertificateSummary {
		return types.CertificateSummary{CertificateArn: aws.String(arn), DomainName: aws.String(domain), Type: typ, Status: types.CertificateStatusIssued, RenewalEligibility: renewal, NotAfter: notAfter}
	}
	return fakeACM{
		summaries: []types.CertificateSummary{
			cert("arn:1", "*.example.com", types.CertificateTypeAmazonIssued, types.RenewalEligibilityEligible, at(61)),
			cert("arn:2", "api.example.com", types.CertificateTypeImported, types.RenewalEligibilityIneligible, at(12)),
			cert("arn:3", "legacy.example.internal", types.CertificateTypeImported, types.RenewalEligibilityIneligible, at(203)),
			cert("arn:5", "old.example.com", types.CertificateTypeAmazonIssued, types.RenewalEligibilityIneligible, at(-900)),
			cert("arn:6", "api.example.org", types.CertificateTypeAmazonIssued, types.RenewalEligibilityIneligible, at(-770)),
			{CertificateArn: aws.String("arn:4"), DomainName: aws.String("pending.example.com"), Type: types.CertificateTypeAmazonIssued, Status: types.CertificateStatusPendingValidation},
		},
		inUseBy: map[string][]string{"arn:2": {"lb-a", "lb-b"}, "arn:6": {"lb-c", "lb-d", "cf-e"}},
	}
}

type acmCall struct{ profile, region string }

func runAWSWith(t *testing.T, terminal bool, f fakeACM, region string, args ...string) (code int, stdout, stderr string, call acmCall) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"aws"}, args...), Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
		NewACM: func(_ context.Context, profile, r string) (acm.API, string, error) {
			call = acmCall{profile, r}
			if r == "" {
				r = region
			}
			return f, r, nil
		},
	})
	return code, out.String(), errOut.String(), call
}

func TestAWSText(t *testing.T) {
	code, stdout, stderr, call := runAWSWith(t, true, sampleACM(), "", "--profile", "production", "--region", "us-east-1")

	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d for an expiring certificate; stderr = %s", code, ExitFindings, stderr)
	}
	if call != (acmCall{"production", "us-east-1"}) {
		t.Errorf("client built with %+v, want the --profile and --region given", call)
	}
	lines := strings.Split(stdout, "\n")
	want := []string{
		"  expired   api.example.org          770 days ago  ",
		"  expired   old.example.com          900 days ago  ",
		"  expiring  api.example.com          12 days       ",
		"  ok        *.example.com            61 days       ",
		"  ok        legacy.example.internal  203 days      ",
	}
	for i, prefix := range want {
		if !strings.HasPrefix(lines[i+1], prefix) {
			t.Errorf("line %d = %q, want prefix %q", i+1, lines[i+1], prefix)
		}
	}
	for _, note := range []string{"imported, in use by 2 resources", "renews itself", "imported, not in use", "does not renew, in use by 3 resources", "does not renew, not in use"} {
		if !strings.Contains(stdout, note) {
			t.Errorf("stdout = %q, want the note %q", stdout, note)
		}
	}
	if strings.Contains(stdout, "pending.example.com") {
		t.Errorf("stdout lists a certificate that was never issued:\n%s", stdout)
	}
}

func TestAWSJSON(t *testing.T) {
	code, stdout, _, _ := runAWSWith(t, false, sampleACM(), "eu-west-1")

	if code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
	var got struct {
		Results []map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\n%s", err, stdout)
	}
	if len(got.Results) != 5 {
		t.Fatalf("len(results) = %d, want 5; the certificate never issued is left out", len(got.Results))
	}
	var info struct {
		ARN      string   `json:"arn"`
		Imported bool     `json:"imported"`
		InUseBy  []string `json:"in_use_by"`
	}
	if err := json.Unmarshal(got.Results[1]["acm"], &info); err != nil || info.ARN != "arn:2" || !info.Imported || len(info.InUseBy) != 2 {
		t.Errorf("results[1].acm = %s, want the imported certificate used twice", got.Results[1]["acm"])
	}
	if string(got.Results[1]["trusted"]) != "null" {
		t.Errorf("results[1].trusted = %s, want null for an ACM certificate", got.Results[1]["trusted"])
	}
}

func TestAWSErrors(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform acm:ListCertificates"}
	tests := []struct {
		name     string
		f        fakeACM
		region   string
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "no region", f: sampleACM(), region: "", wantCode: ExitUsage, wantErr: CodeAWSNotConfigured},
		{name: "access denied", f: fakeACM{listErr: denied}, region: "us-east-1", wantCode: ExitFailure, wantErr: CodeAWSAccessDenied},
		{name: "other failure", f: fakeACM{listErr: errors.New("connection reset")}, region: "us-east-1", wantCode: ExitFailure, wantErr: CodeAWSRequestFailed},
		{name: "targets are not accepted", f: sampleACM(), region: "us-east-1", args: []string{"example.com"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr, _ := runAWSWith(t, false, tt.f, tt.region, tt.args...)

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

func TestAWSHelp(t *testing.T) {
	code, stdout, _, _ := runAWSWith(t, true, sampleACM(), "us-east-1", "--help")

	if code != ExitOK || stdout != awsUsage {
		t.Errorf("exit code = %d, stdout = %q; want 0 and the aws help", code, stdout)
	}
}
