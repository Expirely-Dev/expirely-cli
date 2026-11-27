package acm

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

type fakeACM struct {
	pages      [][]types.CertificateSummary
	inUseBy    map[string][]string
	describeFn func(arn string) error

	mu        sync.Mutex
	listInput []*sdk.ListCertificatesInput
}

func (f *fakeACM) ListCertificates(_ context.Context, in *sdk.ListCertificatesInput, _ ...func(*sdk.Options)) (*sdk.ListCertificatesOutput, error) {
	f.mu.Lock()
	f.listInput = append(f.listInput, in)
	f.mu.Unlock()
	page := 0
	if in.NextToken != nil {
		page = int(aws.ToString(in.NextToken)[0] - '0')
	}
	out := &sdk.ListCertificatesOutput{CertificateSummaryList: f.pages[page]}
	if page+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + page + 1)))
	}
	return out, nil
}

func (f *fakeACM) DescribeCertificate(_ context.Context, in *sdk.DescribeCertificateInput, _ ...func(*sdk.Options)) (*sdk.DescribeCertificateOutput, error) {
	arn := aws.ToString(in.CertificateArn)
	if f.describeFn != nil {
		if err := f.describeFn(arn); err != nil {
			return nil, err
		}
	}
	return &sdk.DescribeCertificateOutput{Certificate: &types.CertificateDetail{InUseBy: f.inUseBy[arn]}}, nil
}

func summary(arn, domain string, typ types.CertificateType, notAfter *time.Time) types.CertificateSummary {
	return types.CertificateSummary{
		CertificateArn: aws.String(arn),
		DomainName:     aws.String(domain),
		Type:           typ,
		Status:         types.CertificateStatusIssued,
		NotAfter:       notAfter,
	}
}

func TestListReadsEveryPageAndKeyType(t *testing.T) {
	end := time.Date(2027, 1, 26, 0, 0, 0, 0, time.UTC)
	f := &fakeACM{
		pages: [][]types.CertificateSummary{
			{summary("arn:1", "api.example.com", types.CertificateTypeImported, &end)},
			{summary("arn:2", "*.example.com", types.CertificateTypeAmazonIssued, &end), summary("arn:3", "pending.example.com", types.CertificateTypeAmazonIssued, nil)},
		},
		inUseBy: map[string][]string{"arn:1": {"arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1", "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/b/2"}},
	}

	got, err := List(context.Background(), f)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len(certificates) = %d, want 3 across both pages", len(got))
	}
	if got[0].Domain != "api.example.com" || !got[0].Imported() || len(got[0].InUseBy) != 2 {
		t.Errorf("certificates[0] = %+v, want the imported certificate used by two load balancers", got[0])
	}
	if got[1].Imported() || got[2].NotAfter != nil {
		t.Errorf("certificates[1:] = %+v, want an ACM-issued one and one never issued", got[1:])
	}
	keyTypes := f.listInput[0].Includes.KeyTypes
	if !slices.Contains(keyTypes, types.KeyAlgorithmEcPrime256v1) || !slices.Contains(keyTypes, types.KeyAlgorithmRsa2048) {
		t.Errorf("ListCertificates key types = %v, want every key type, not the RSA 2048 default", keyTypes)
	}
}

func TestListReturnsDescribeErrors(t *testing.T) {
	end := time.Now()
	f := &fakeACM{
		pages:      [][]types.CertificateSummary{{summary("arn:1", "a.example.com", types.CertificateTypeImported, &end)}},
		describeFn: func(string) error { return errors.New("throttled") },
	}

	_, err := List(context.Background(), f)

	if err == nil || !strings.Contains(err.Error(), "describe ACM certificate arn:1: throttled") {
		t.Fatalf("List() error = %v, want the describe error with the certificate ARN", err)
	}
}

func TestListStopsDescribingAfterTheFirstError(t *testing.T) {
	end := time.Now()
	var summaries []types.CertificateSummary
	for i := range 40 {
		summaries = append(summaries, summary(fmt.Sprintf("arn:%d", i), "a.example.com", types.CertificateTypeImported, &end))
	}
	var calls atomic.Int32
	f := &fakeACM{
		pages: [][]types.CertificateSummary{summaries},
		describeFn: func(arn string) error {
			calls.Add(1)
			return errors.New("throttled " + arn)
		},
	}

	_, err := List(context.Background(), f)

	if err == nil || !strings.Contains(err.Error(), "throttled") || errors.Is(err, context.Canceled) {
		t.Errorf("List() error = %v, want the first describe error, not the cancellation it caused", err)
	}
	if n := calls.Load(); n > describeConcurrency+1 {
		t.Errorf("DescribeCertificate called %d times, want at most %d after the first error", n, describeConcurrency+1)
	}
}
