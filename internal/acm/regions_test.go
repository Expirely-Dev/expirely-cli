package acm

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
)

type fakeRegions struct {
	pages [][]string
	asked []accounttypes.RegionOptStatus
	err   error
}

func (f *fakeRegions) ListRegions(_ context.Context, in *account.ListRegionsInput, _ ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.asked = in.RegionOptStatusContains
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	out := &account.ListRegionsOutput{}
	for _, name := range f.pages[page] {
		out.Regions = append(out.Regions, accounttypes.Region{RegionName: aws.String(name)})
	}
	if page+1 < len(f.pages) {
		out.NextToken = aws.String("next")
	}
	return out, nil
}

func TestEnabledRegionsReadsEveryPageSorted(t *testing.T) {
	api := &fakeRegions{pages: [][]string{{"us-east-1", "ap-south-1"}, {"eu-west-1"}}}

	got, err := EnabledRegions(context.Background(), api)

	if err != nil || strings.Join(got, ",") != "ap-south-1,eu-west-1,us-east-1" {
		t.Errorf("EnabledRegions() = %v, %v; want every page, sorted", got, err)
	}
	want := []accounttypes.RegionOptStatus{accounttypes.RegionOptStatusEnabled, accounttypes.RegionOptStatusEnabledByDefault}
	if !slices.Equal(api.asked, want) {
		t.Errorf("asked for regions %v, want only %v", api.asked, want)
	}
}

func TestEnabledRegionsKeepsTheCause(t *testing.T) {
	cause := errors.New("access denied")

	_, err := EnabledRegions(context.Background(), &fakeRegions{err: cause})

	if !errors.Is(err, cause) {
		t.Errorf("EnabledRegions() error = %v, want it to wrap %v", err, cause)
	}
}
