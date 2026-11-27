// Package gcp reads the certificates a Google Cloud project serves from its
// load balancers: the Compute Engine SSL certificates, global and regional,
// with the target HTTPS and SSL proxies that use them, and the certificates
// in Certificate Manager, with the resources that use them. It calls the
// REST APIs directly with list methods only, so the IAM permissions it
// needs are compute.sslCertificates.list, compute.targetHttpsProxies.list,
// compute.targetSslProxies.list, certificatemanager.locations.list and
// certificatemanager.certs.list.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
)

// Default endpoints of the APIs List reads.
const (
	DefaultComputeEndpoint            = "https://compute.googleapis.com/compute/v1/"
	DefaultCertificateManagerEndpoint = "https://certificatemanager.googleapis.com/v1/"
)

// Sources of a Certificate. They are part of the public JSON contract.
const (
	SourceCompute            = "compute"
	SourceCertificateManager = "certificate_manager"
)

// cloudPlatformScope is the only OAuth scope Certificate Manager accepts.
// It does not widen what the credentials can do: IAM decides that, and List
// calls list methods alone.
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// maxBody bounds how much of one API response List reads.
const maxBody = 32 << 20

// locationConcurrency bounds the Certificate Manager calls made at once, one
// per location.
const locationConcurrency = 8

// Certificate is one certificate of the project. Source is SourceCompute or
// SourceCertificateManager. Managed is true for a certificate Google issues
// and renews; a self-managed one was uploaded and is never renewed. NotAfter
// is nil for a managed certificate that was not issued yet. InUseBy holds
// resource paths starting at "projects/".
type Certificate struct {
	Name     string
	Domain   string
	Location string
	Source   string
	Managed  bool
	NotAfter *time.Time
	InUseBy  []string
}

// Service calls the Google Cloud REST APIs with Client, which signs
// requests, at the endpoints it names.
type Service struct {
	Client                     *http.Client
	ComputeEndpoint            string
	CertificateManagerEndpoint string
}

// NewService builds a Service that signs in with Application Default
// Credentials.
func NewService(ctx context.Context) (*Service, error) {
	client, err := google.DefaultClient(ctx, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("find Google Cloud credentials: %w", err)
	}
	return &Service{Client: client, ComputeEndpoint: DefaultComputeEndpoint, CertificateManagerEndpoint: DefaultCertificateManagerEndpoint}, nil
}

// APIError is an error response of a Google Cloud API. Reason is the first
// ErrorInfo reason Google gives, such as SERVICE_DISABLED or
// BILLING_DISABLED, and is empty when it gives none.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Google Cloud answered %d: %s", e.Code, e.Message)
}

// Disabled reports whether the project cannot use the API at all, because
// the API or the project's billing is disabled.
func (e *APIError) Disabled() bool {
	return e.Reason == "SERVICE_DISABLED" || e.Reason == "BILLING_DISABLED"
}

// Listing is what List read from a project. Unreachable names each place
// Google could not read, as source:location such as "compute:us-east7" or
// "certificate_manager:us-east1"; Certificates then lacks whatever that
// place holds.
type Listing struct {
	Certificates []Certificate
	Unreachable  []string
}

// List returns every certificate of project: the Compute SSL certificates,
// then the Certificate Manager ones. A region or location Google cannot
// reach is listed in Unreachable rather than failing the whole listing. A
// project with Certificate Manager disabled has none there, which is not an
// error; a project with Compute disabled is, since it serves no load
// balancer at all.
func List(ctx context.Context, svc *Service, project string) (Listing, error) {
	var l Listing
	if err := computeCertificates(ctx, svc, project, &l); err != nil {
		return Listing{}, err
	}
	err := managerCertificates(ctx, svc, project, &l)
	var apiErr *APIError
	if err != nil && (!errors.As(err, &apiErr) || apiErr.Reason != "SERVICE_DISABLED") {
		return Listing{}, err
	}
	slices.Sort(l.Unreachable)
	l.Unreachable = slices.Compact(l.Unreachable)
	return l, nil
}

// unreachable records places, as Google names them, that source could not
// read, by location alone: "regions/us-east7" and
// "projects/p/locations/us-east1" become "us-east7" and "us-east1".
func (l *Listing) unreachable(source string, places []string) {
	for _, p := range places {
		l.Unreachable = append(l.Unreachable, source+":"+p[strings.LastIndex(p, "/")+1:])
	}
}

type sslCertificate struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	SelfLink string   `json:"selfLink"`
	SANs     []string `json:"subjectAlternativeNames"`
	Expire   string   `json:"expireTime"`
	Managed  *struct {
		Domains []string `json:"domains"`
	} `json:"managed"`
}

type proxy struct {
	SelfLink        string   `json:"selfLink"`
	SslCertificates []string `json:"sslCertificates"`
}

// partial makes an aggregated list answer with what it could read and name
// the regions it could not, as Google recommends, instead of failing whole.
const partial = "?returnPartialSuccess=true"

func computeCertificates(ctx context.Context, svc *Service, project string, l *Listing) error {
	users, err := proxyUsers(ctx, svc, project, l)
	if err != nil {
		return err
	}
	err = list(ctx, svc.Client, computeURL(svc, project, "aggregated/sslCertificates"+partial), func(p struct {
		paged
		Unreachables []string `json:"unreachables"`
		Items        map[string]struct {
			SslCertificates []sslCertificate `json:"sslCertificates"`
		} `json:"items"`
	}) error {
		l.unreachable(SourceCompute, p.Unreachables)
		for scope, items := range p.Items {
			for _, c := range items.SslCertificates {
				domains := c.SANs
				if len(domains) == 0 && c.Managed != nil {
					domains = c.Managed.Domains
				}
				cert, err := certificate(c.Name, domains, c.Expire)
				if err != nil {
					return err
				}
				cert.Location = strings.TrimPrefix(scope, "regions/")
				cert.Source = SourceCompute
				cert.Managed = c.Type == "MANAGED"
				cert.InUseBy = users[resourcePath(c.SelfLink)]
				l.Certificates = append(l.Certificates, cert)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list SSL certificates: %w", err)
	}
	return nil
}

// proxyUsers maps each Compute SSL certificate, by resource path, to the
// target HTTPS and SSL proxies that list it. A region it cannot reach goes
// to l's Unreachable, since a certificate there may be in use.
func proxyUsers(ctx context.Context, svc *Service, project string, l *Listing) (map[string][]string, error) {
	users := map[string][]string{}
	add := func(proxies []proxy) {
		for _, p := range proxies {
			for _, c := range p.SslCertificates {
				users[resourcePath(c)] = append(users[resourcePath(c)], resourcePath(p.SelfLink))
			}
		}
	}
	err := list(ctx, svc.Client, computeURL(svc, project, "aggregated/targetHttpsProxies"+partial), func(p struct {
		paged
		Unreachables []string `json:"unreachables"`
		Items        map[string]struct {
			TargetHTTPSProxies []proxy `json:"targetHttpsProxies"`
		} `json:"items"`
	}) error {
		l.unreachable(SourceCompute, p.Unreachables)
		for _, items := range p.Items {
			add(items.TargetHTTPSProxies)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list target HTTPS proxies: %w", err)
	}
	err = list(ctx, svc.Client, computeURL(svc, project, "global/targetSslProxies"), func(p struct {
		paged
		Items []proxy `json:"items"`
	}) error {
		add(p.Items)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list target SSL proxies: %w", err)
	}
	return users, nil
}

type managerCertificate struct {
	Name    string   `json:"name"`
	SANs    []string `json:"sanDnsnames"`
	Expire  string   `json:"expireTime"`
	Managed *struct {
		Domains []string `json:"domains"`
	} `json:"managed"`
	UsedBy []struct {
		Name string `json:"name"`
	} `json:"usedBy"`
}

// managerCertificates lists the project's Certificate Manager locations,
// then the certificates of each, locationConcurrency locations at a time,
// into l. The first failure stops the calls not yet made and is the error
// returned.
func managerCertificates(ctx context.Context, svc *Service, project string, l *Listing) error {
	var locations []string
	err := list(ctx, svc.Client, managerURL(svc, "projects/"+url.PathEscape(project)+"/locations"), func(p struct {
		paged
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}) error {
		for _, l := range p.Locations {
			locations = append(locations, l.LocationID)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("list Certificate Manager locations: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	byLocation := make([]Listing, len(locations))
	sem := make(chan struct{}, locationConcurrency)
	var wg sync.WaitGroup
admit:
	for i, loc := range locations {
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
			found, err := managerLocation(ctx, svc, project, loc)
			if err != nil {
				cancel(fmt.Errorf("list Certificate Manager certificates in %s: %w", loc, err))
				return
			}
			byLocation[i] = found
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	for _, found := range byLocation {
		l.Certificates = append(l.Certificates, found.Certificates...)
		l.Unreachable = append(l.Unreachable, found.Unreachable...)
	}
	return nil
}

func managerLocation(ctx context.Context, svc *Service, project, location string) (Listing, error) {
	var l Listing
	u := managerURL(svc, "projects/"+url.PathEscape(project)+"/locations/"+url.PathEscape(location)+"/certificates")
	err := list(ctx, svc.Client, u, func(p struct {
		paged
		Unreachable  []string             `json:"unreachable"`
		Certificates []managerCertificate `json:"certificates"`
	}) error {
		l.unreachable(SourceCertificateManager, p.Unreachable)
		for _, c := range p.Certificates {
			domains := c.SANs
			if len(domains) == 0 && c.Managed != nil {
				domains = c.Managed.Domains
			}
			cert, err := certificate(c.Name[strings.LastIndex(c.Name, "/")+1:], domains, c.Expire)
			if err != nil {
				return err
			}
			cert.Location = location
			cert.Source = SourceCertificateManager
			cert.Managed = c.Managed != nil
			for _, user := range c.UsedBy {
				cert.InUseBy = append(cert.InUseBy, resourcePath(user.Name))
			}
			l.Certificates = append(l.Certificates, cert)
		}
		return nil
	})
	return l, err
}

// certificate builds the fields both APIs share: the domain is the first
// name the certificate covers, or its own name when it lists none, and an
// empty expireTime leaves NotAfter nil.
func certificate(name string, domains []string, expire string) (Certificate, error) {
	cert := Certificate{Name: name, Domain: name}
	if len(domains) > 0 {
		cert.Domain = domains[0]
	}
	if expire != "" {
		at, err := time.Parse(time.RFC3339, expire)
		if err != nil {
			return Certificate{}, fmt.Errorf("certificate %s has expireTime %q: %w", name, expire, err)
		}
		cert.NotAfter = &at
	}
	return cert, nil
}

func computeURL(svc *Service, project, path string) string {
	return strings.TrimSuffix(svc.ComputeEndpoint, "/") + "/projects/" + url.PathEscape(project) + "/" + path
}

func managerURL(svc *Service, path string) string {
	return strings.TrimSuffix(svc.CertificateManagerEndpoint, "/") + "/" + path
}

// paged is embedded in every page type list decodes; the token names the
// next page and is empty on the last one.
type paged struct {
	NextPageToken string `json:"nextPageToken"`
}

func (p paged) next() string { return p.NextPageToken }

// list calls the list method at u, once per page, and hands each decoded
// page to each.
func list[P interface{ next() string }](ctx context.Context, client *http.Client, u string, each func(P) error) error {
	for token := ""; ; {
		pageURL := u
		if token != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			pageURL += sep + "pageToken=" + url.QueryEscape(token)
		}
		body, err := get(ctx, client, pageURL)
		if err != nil {
			return err
		}
		var p P
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("read %s: %w", u, err)
		}
		if err := each(p); err != nil {
			return err
		}
		if token = p.next(); token == "" {
			return nil
		}
	}
}

func get(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
				Details []struct {
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		apiErr := &APIError{Code: resp.StatusCode, Message: e.Error.Message}
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		for _, d := range e.Error.Details {
			if d.Reason != "" {
				apiErr.Reason = d.Reason
				break
			}
		}
		return nil, apiErr
	}
	return body, nil
}

// resourcePath returns a resource name from "projects/" on, so a reference,
// a self link and a full resource name such as
// //compute.googleapis.com/projects/p/global/targetHttpsProxies/x name the
// same resource whatever their host or API version.
func resourcePath(u string) string {
	if i := strings.Index(u, "projects/"); i >= 0 {
		return u[i:]
	}
	return u
}
