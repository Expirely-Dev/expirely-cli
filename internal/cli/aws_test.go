package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/smithy-go"
	"github.com/expirely-dev/expirely-cli/internal/acm"
	"github.com/expirely-dev/expirely-cli/internal/scan"
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

// fakeAccount answers Client with the client of each region in clients,
// or fallback for a region it does not name.
type fakeAccount struct {
	region     string
	clients    map[string]acm.API
	fallback   acm.API
	regions    []string
	regionsErr error
}

func (f fakeAccount) Region() string { return f.region }

func (f fakeAccount) Client(region string) acm.API {
	if c, ok := f.clients[region]; ok {
		return c
	}
	return f.fallback
}

func (f fakeAccount) EnabledRegions(context.Context) ([]string, error) {
	return f.regions, f.regionsErr
}

type acmCall struct{ profile, region string }

func runAWSWith(t *testing.T, terminal bool, f fakeACM, region string, args ...string) (code int, stdout, stderr string, call acmCall) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"tls", "aws"}, args...), Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
		NewACM: func(_ context.Context, profile, r string) (acm.Account, error) {
			call = acmCall{profile, r}
			return fakeAccount{region: region, fallback: f}, nil
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
	var arns []string
	for _, r := range got.Results {
		var a struct {
			ARN string `json:"arn"`
		}
		_ = json.Unmarshal(r["acm"], &a)
		arns = append(arns, a.ARN)
	}
	if want := "arn:6,arn:5,arn:2,arn:1,arn:3"; strings.Join(arns, ",") != want {
		t.Errorf("results order = %v, want %s: expired before expiring, in use before unused, fewest days first", arns, want)
	}
	if err := json.Unmarshal(got.Results[2]["acm"], &info); err != nil || info.ARN != "arn:2" || !info.Imported || len(info.InUseBy) != 2 {
		t.Errorf("results[2].acm = %s, want the imported certificate used twice", got.Results[2]["acm"])
	}
	var tlsInfo struct {
		Trusted json.RawMessage `json:"trusted"`
	}
	if err := json.Unmarshal(got.Results[2]["tls"], &tlsInfo); err != nil || string(tlsInfo.Trusted) != "null" {
		t.Errorf("results[2].tls = %s, want trusted null for an ACM certificate", got.Results[2]["tls"])
	}
	if string(got.Results[2]["source"]) != `"aws_acm"` {
		t.Errorf("results[2].source = %s, want \"aws_acm\"", got.Results[2]["source"])
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

func TestACMFindings(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	soon, later := now.Add(12*day), now.Add(61*day)
	certs := []acm.Certificate{
		{ARN: "arn:1", Domain: "api.example.com", Type: "IMPORTED", Status: "ISSUED", NotAfter: &soon, InUseBy: []string{"lb-a", "lb-b"}},
		{ARN: "arn:2", Domain: "*.example.com", Type: "AMAZON_ISSUED", Status: "ISSUED", RenewalEligibility: "ELIGIBLE", NotAfter: &later},
		{ARN: "arn:3", Domain: "pending.example.com", Type: "AMAZON_ISSUED", Status: "PENDING_VALIDATION"},
	}

	got := acmFindings(certs, "us-east-1", now, 30*day)

	if len(got) != 2 {
		t.Fatalf("len(findings) = %d, want 2; a certificate never issued has no end date", len(got))
	}
	if f := got[0]; f.Target != "api.example.com" || f.Status != scan.StatusExpiring || *f.DaysLeft != 12 || !f.ACM.Imported || len(f.ACM.InUseBy) != 2 {
		t.Errorf("findings[0] = %+v, acm = %+v; want an expiring imported certificate used twice", f, f.ACM)
	}
	if f := got[1]; f.Status != scan.StatusOK || f.ACM.Imported || f.ACM.InUseBy == nil {
		t.Errorf("findings[1] = %+v, acm = %+v; want an ok ACM-issued certificate with an empty in_use_by", f, f.ACM)
	}
}

func okACMCert(arn, domain string) fakeACM {
	notAfter := time.Now().AddDate(0, 0, 200)
	return fakeACM{summaries: []types.CertificateSummary{
		{CertificateArn: aws.String(arn), DomainName: aws.String(domain), Type: types.CertificateTypeAmazonIssued, Status: types.CertificateStatusIssued, RenewalEligibility: types.RenewalEligibilityEligible, NotAfter: &notAfter},
	}}
}

func runAWSAccount(t *testing.T, terminal bool, acct fakeAccount, args ...string) (code int, stdout, stderr string, call acmCall) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"tls", "aws"}, args...), Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
		NewACM: func(_ context.Context, profile, region string) (acm.Account, error) {
			call = acmCall{profile, region}
			return acct, nil
		},
	})
	return code, out.String(), errOut.String(), call
}

type awsReport struct {
	Unreadable []string `json:"unreadable"`
	Results    []struct {
		Target string `json:"target"`
		ACM    struct {
			Region string `json:"region"`
		} `json:"acm"`
	} `json:"results"`
}

func decodeAWS(t *testing.T, stdout, stderr string) awsReport {
	t.Helper()
	var r awsReport
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return r
}

func regionsOf(r awsReport) string {
	var got []string
	for _, res := range r.Results {
		got = append(got, res.Target+"@"+res.ACM.Region)
	}
	sort.Strings(got)
	return strings.Join(got, ",")
}

func TestAWSEveryRegion(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "explicit deny in a service control policy"}
	acct := fakeAccount{
		region:  "eu-west-1",
		regions: []string{"ap-south-1", "eu-west-1", "us-east-1"},
		clients: map[string]acm.API{
			"us-east-1":  okACMCert("arn:cf", "cdn.example.com"),
			"eu-west-1":  okACMCert("arn:alb", "api.example.com"),
			"ap-south-1": fakeACM{listErr: denied},
		},
	}

	t.Run("json", func(t *testing.T) {
		code, stdout, stderr, call := runAWSAccount(t, false, acct, "--region", "all")

		r := decodeAWS(t, stdout, stderr)
		if got, want := regionsOf(r), "api.example.com@eu-west-1,cdn.example.com@us-east-1"; got != want {
			t.Errorf("results = %s, want %s: every readable region, each result naming its region", got, want)
		}
		if strings.Join(r.Unreadable, ",") != "acm:ap-south-1" {
			t.Errorf("unreadable = %v, want [acm:ap-south-1]", r.Unreadable)
		}
		if code != ExitFailure {
			t.Errorf("exit code = %d, want %d: the certificates read are ok, but a region was not read", code, ExitFailure)
		}
		if call.region != "" {
			t.Errorf("account opened with region %q, want none for every region", call.region)
		}
	})
	t.Run("text", func(t *testing.T) {
		_, stdout, stderr, _ := runAWSAccount(t, true, acct, "--region", "all")

		if !strings.Contains(stdout, "cdn.example.com") || !strings.Contains(stdout, "api.example.com") {
			t.Errorf("stdout = %q, want both certificates", stdout)
		}
		if !strings.Contains(stderr, "could not read acm:ap-south-1") {
			t.Errorf("stderr = %q, want the region it could not read", stderr)
		}
	})
}

func TestAWSRegionList(t *testing.T) {
	acct := fakeAccount{clients: map[string]acm.API{
		"us-east-1": okACMCert("arn:cf", "cdn.example.com"),
		"eu-west-1": okACMCert("arn:alb", "api.example.com"),
	}, fallback: fakeACM{listErr: errors.New("this region was not asked for")}}

	code, stdout, stderr, _ := runAWSAccount(t, false, acct, "--region", "us-east-1, eu-west-1,us-east-1")

	r := decodeAWS(t, stdout, stderr)
	if got, want := regionsOf(r), "api.example.com@eu-west-1,cdn.example.com@us-east-1"; got != want || len(r.Unreadable) != 0 {
		t.Errorf("results = %s, unreadable = %v; want %s from the two regions named, once each", got, r.Unreadable, want)
	}
	if code != ExitOK {
		t.Errorf("exit code = %d, want 0; stderr = %s", code, stderr)
	}
}

func TestAWSRegionErrors(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform ec2:DescribeRegions"}
	tests := []struct {
		name     string
		acct     fakeAccount
		args     []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "not a region",
			acct:     fakeAccount{fallback: sampleACM()},
			args:     []string{"--region", "us-east1"},
			wantCode: ExitUsage,
			wantErr:  CodeInvalidFlag,
		},
		{
			name:     "regions cannot be listed",
			acct:     fakeAccount{regionsErr: denied},
			args:     []string{"--region", "all"},
			wantCode: ExitFailure,
			wantErr:  CodeAWSAccessDenied,
		},
		{
			name:     "no region can be read",
			acct:     fakeAccount{regions: []string{"eu-west-1", "us-east-1"}, fallback: fakeACM{listErr: &smithy.GenericAPIError{Code: "UnrecognizedClientException"}}},
			args:     []string{"--region", "all"},
			wantCode: ExitFailure,
			wantErr:  CodeAWSAccessDenied,
		},
		{
			name:     "no enabled region",
			acct:     fakeAccount{},
			args:     []string{"--region", "all"},
			wantCode: ExitFailure,
			wantErr:  CodeAWSRequestFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr, _ := runAWSAccount(t, false, tt.acct, tt.args...)

			var env envelope
			if err := json.Unmarshal([]byte(stderr), &env); err != nil || env.Error.Code != tt.wantErr || code != tt.wantCode {
				t.Errorf("exit code = %d, stderr = %s; want %d and the %q envelope", code, stderr, tt.wantCode, tt.wantErr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}
