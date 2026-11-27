// Package acm reads the certificates AWS Certificate Manager holds in one
// account and region. It only calls ListCertificates and
// DescribeCertificate, so the IAM permissions it needs are
// acm:ListCertificates and acm:DescribeCertificate.
package acm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// API is the part of the ACM client List calls.
type API interface {
	ListCertificates(ctx context.Context, in *sdk.ListCertificatesInput, opts ...func(*sdk.Options)) (*sdk.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, in *sdk.DescribeCertificateInput, opts ...func(*sdk.Options)) (*sdk.DescribeCertificateOutput, error)
}

// Certificate is one certificate in ACM. NotAfter is nil for a certificate
// that was never issued, such as one pending validation.
type Certificate struct {
	ARN                string
	Domain             string
	Type               string
	Status             string
	RenewalEligibility string
	NotAfter           *time.Time
	InUseBy            []string
}

// Imported reports whether the certificate was imported into ACM. ACM never
// renews an imported certificate.
func (c Certificate) Imported() bool { return c.Type == string(types.CertificateTypeImported) }

// describeConcurrency bounds DescribeCertificate calls, which ACM rate
// limits per account.
const describeConcurrency = 8

// List returns every certificate of every key type, in the order ACM lists
// them, each with the resources that use it. ListCertificates alone would
// leave out every key type other than RSA 2048.
func List(ctx context.Context, api API) ([]Certificate, error) {
	in := &sdk.ListCertificatesInput{Includes: &types.Filters{KeyTypes: types.KeyAlgorithm("").Values()}}
	var certs []Certificate
	pages := sdk.NewListCertificatesPaginator(api, in)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ACM certificates: %w", err)
		}
		for _, s := range page.CertificateSummaryList {
			certs = append(certs, Certificate{
				ARN:                aws.ToString(s.CertificateArn),
				Domain:             aws.ToString(s.DomainName),
				Type:               string(s.Type),
				Status:             string(s.Status),
				RenewalEligibility: string(s.RenewalEligibility),
				NotAfter:           s.NotAfter,
			})
		}
	}
	if err := describe(ctx, api, certs); err != nil {
		return nil, err
	}
	return certs, nil
}

// describe fills in InUseBy for every certificate, describeConcurrency at a
// time. The first failure stops the calls not yet made, and is the error
// describe returns.
func describe(ctx context.Context, api API, certs []Certificate) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	sem := make(chan struct{}, describeConcurrency)
	var wg sync.WaitGroup
admit:
	for i := range certs {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break admit
		}
		wg.Go(func() {
			defer func() { <-sem }()
			out, err := api.DescribeCertificate(ctx, &sdk.DescribeCertificateInput{CertificateArn: aws.String(certs[i].ARN)})
			if err != nil {
				cancel(fmt.Errorf("describe ACM certificate %s: %w", certs[i].ARN, err))
				return
			}
			if out.Certificate != nil {
				certs[i].InUseBy = out.Certificate.InUseBy
			}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

// NewClient builds an ACM client from the AWS configuration: profile and
// region when given, the environment and shared files otherwise. It returns
// the region the client uses, which is empty when none is configured.
func NewClient(ctx context.Context, profile, region string) (*sdk.Client, string, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("load AWS configuration: %w", err)
	}
	return sdk.NewFromConfig(cfg), cfg.Region, nil
}
