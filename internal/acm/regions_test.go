package acm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeRegions struct {
	names []string
	asked *ec2.DescribeRegionsInput
	err   error
}

func (f *fakeRegions) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.asked = in
	if f.err != nil {
		return nil, f.err
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, name := range f.names {
		out.Regions = append(out.Regions, ec2types.Region{RegionName: aws.String(name)})
	}
	return out, nil
}

func TestEnabledRegionsSortsWhatTheAccountCanUse(t *testing.T) {
	api := &fakeRegions{names: []string{"us-east-1", "ap-south-1", "eu-west-1"}}

	got, err := EnabledRegions(context.Background(), api)

	if err != nil || strings.Join(got, ",") != "ap-south-1,eu-west-1,us-east-1" {
		t.Errorf("EnabledRegions() = %v, %v; want the regions sorted", got, err)
	}
	if api.asked.AllRegions != nil {
		t.Errorf("AllRegions = %v, want unset so regions the account has not opted in to stay out", *api.asked.AllRegions)
	}
}

func TestEnabledRegionsKeepsTheCause(t *testing.T) {
	cause := errors.New("access denied")

	_, err := EnabledRegions(context.Background(), &fakeRegions{err: cause})

	if !errors.Is(err, cause) {
		t.Errorf("EnabledRegions() error = %v, want it to wrap %v", err, cause)
	}
}
