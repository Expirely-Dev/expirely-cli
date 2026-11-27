// Package acm reads the certificates AWS Certificate Manager holds in the
// regions of one account. It only calls ListCertificates and
// DescribeCertificate, plus EC2 DescribeRegions to find the enabled
// regions, so the IAM permissions it needs are acm:ListCertificates,
// acm:DescribeCertificate and, for every region, ec2:DescribeRegions.
package acm

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdk "github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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

// Account reads ACM in the regions of one AWS account, with one set of
// credentials. Region is the region the configuration names, empty when it
// names none. EnabledRegions lists the regions the account can use, those
// enabled by default and those opted in, sorted.
type Account interface {
	Region() string
	Client(region string) API
	EnabledRegions(ctx context.Context) ([]string, error)
}

// RegionsAPI is the part of the EC2 client EnabledRegions calls.
type RegionsAPI interface {
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// Session is the Account of one AWS configuration.
type Session struct {
	cfg aws.Config
}

// NewSession loads the AWS configuration: profile and region when given,
// the environment and shared files otherwise. Clients made from it share
// its credentials, so they are resolved once for every region.
func NewSession(ctx context.Context, profile, region string) (*Session, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return &Session{cfg: cfg}, nil
}

// Region returns the region the configuration names, or "".
func (s *Session) Region() string { return s.cfg.Region }

// Client returns an ACM client for region.
func (s *Session) Client(region string) API {
	return sdk.NewFromConfig(s.cfg, func(o *sdk.Options) { o.Region = region })
}

// EnabledRegions lists the account's enabled regions with
// ec2:DescribeRegions, asked in the configured region or, without one, in
// us-east-1. The AWS managed policy ReadOnlyAccess grants it through
// ec2:Describe*, and read-only roles that deny account:ListRegions still
// allow it.
func (s *Session) EnabledRegions(ctx context.Context) ([]string, error) {
	region := cmp.Or(s.cfg.Region, "us-east-1")
	return EnabledRegions(ctx, ec2.NewFromConfig(s.cfg, func(o *ec2.Options) { o.Region = region }))
}

// EnabledRegions lists, sorted, the regions api reports as enabled for the
// account: those enabled by default and those opted in. DescribeRegions
// leaves out regions the account has not opted in to unless asked for all
// of them, which EnabledRegions does not ask.
func EnabledRegions(ctx context.Context, api RegionsAPI) ([]string, error) {
	out, err := api.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("list the enabled AWS regions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	slices.Sort(regions)
	return regions, nil
}
