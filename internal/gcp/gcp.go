// Package gcp reads the certificates a Google Cloud project serves from its
// load balancers: the Compute Engine SSL certificates, global and regional,
// and the target HTTPS and SSL proxies that use them. It calls the Compute
// REST API directly with three list methods, so the IAM permissions it
// needs are compute.sslCertificates.list, compute.targetHttpsProxies.list
// and compute.targetSslProxies.list.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

// DefaultEndpoint is the Compute Engine REST API.
const DefaultEndpoint = "https://compute.googleapis.com/compute/v1/"

const readOnlyScope = "https://www.googleapis.com/auth/compute.readonly"

// maxBody bounds how much of one API response List reads.
const maxBody = 32 << 20

// Certificate is one SSL certificate of the project. Managed is true for a
// certificate Google issues and renews; a self-managed one was uploaded and
// is never renewed. NotAfter is nil for a managed certificate that was not
// issued yet.
type Certificate struct {
	Name     string
	Domain   string
	Location string
	Managed  bool
	NotAfter *time.Time
	InUseBy  []string
}

// Service calls the Compute REST API at Endpoint with Client, which signs
// requests.
type Service struct {
	Client   *http.Client
	Endpoint string
}

// NewService builds a Service that signs in with Application Default
// Credentials, read-only.
func NewService(ctx context.Context) (*Service, error) {
	client, err := google.DefaultClient(ctx, readOnlyScope)
	if err != nil {
		return nil, fmt.Errorf("find Google Cloud credentials: %w", err)
	}
	return &Service{Client: client, Endpoint: DefaultEndpoint}, nil
}

// APIError is an error response of the Compute API. Reason is the first
// ErrorInfo reason Google gives, such as SERVICE_DISABLED or
// BILLING_DISABLED, and is empty when it gives none.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

// Disabled reports whether the project cannot use Compute Engine at all,
// because its API or its billing is disabled; such a project has no SSL
// certificates to list.
func (e *APIError) Disabled() bool {
	return e.Reason == "SERVICE_DISABLED" || e.Reason == "BILLING_DISABLED"
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Google Cloud answered %d: %s", e.Code, e.Message)
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

// List returns every SSL certificate of project, global and regional, each
// with the target proxies that serve it.
func List(ctx context.Context, svc *Service, project string) ([]Certificate, error) {
	users, err := proxyUsers(ctx, svc, project)
	if err != nil {
		return nil, err
	}
	var certs []Certificate
	err = pages(ctx, svc, project, "aggregated/sslCertificates", func(body []byte) error {
		var page struct {
			Items map[string]struct {
				SslCertificates []sslCertificate `json:"sslCertificates"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for scope, list := range page.Items {
			for _, c := range list.SslCertificates {
				cert, err := fromCompute(c, scope)
				if err != nil {
					return err
				}
				cert.InUseBy = users[resourcePath(c.SelfLink)]
				certs = append(certs, cert)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list SSL certificates: %w", err)
	}
	return certs, nil
}

func fromCompute(c sslCertificate, scope string) (Certificate, error) {
	cert := Certificate{
		Name:     c.Name,
		Domain:   c.Name,
		Location: strings.TrimPrefix(scope, "regions/"),
		Managed:  c.Type == "MANAGED",
	}
	switch {
	case len(c.SANs) > 0:
		cert.Domain = c.SANs[0]
	case c.Managed != nil && len(c.Managed.Domains) > 0:
		cert.Domain = c.Managed.Domains[0]
	}
	if c.Expire != "" {
		at, err := time.Parse(time.RFC3339, c.Expire)
		if err != nil {
			return Certificate{}, fmt.Errorf("SSL certificate %s has expireTime %q: %w", c.Name, c.Expire, err)
		}
		cert.NotAfter = &at
	}
	return cert, nil
}

// proxyUsers maps each SSL certificate, by resource path, to the target
// HTTPS and SSL proxies that list it.
func proxyUsers(ctx context.Context, svc *Service, project string) (map[string][]string, error) {
	users := map[string][]string{}
	add := func(proxies []proxy) {
		for _, p := range proxies {
			for _, c := range p.SslCertificates {
				users[resourcePath(c)] = append(users[resourcePath(c)], resourcePath(p.SelfLink))
			}
		}
	}
	err := pages(ctx, svc, project, "aggregated/targetHttpsProxies", func(body []byte) error {
		var page struct {
			Items map[string]struct {
				TargetHTTPSProxies []proxy `json:"targetHttpsProxies"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for _, list := range page.Items {
			add(list.TargetHTTPSProxies)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list target HTTPS proxies: %w", err)
	}
	err = pages(ctx, svc, project, "global/targetSslProxies", func(body []byte) error {
		var page struct {
			Items []proxy `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		add(page.Items)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list target SSL proxies: %w", err)
	}
	return users, nil
}

// pages calls the list method at path for project, once per page, and
// hands each response body to fn.
func pages(ctx context.Context, svc *Service, project, path string, fn func(body []byte) error) error {
	token := ""
	for {
		u := strings.TrimSuffix(svc.Endpoint, "/") + "/projects/" + url.PathEscape(project) + "/" + path
		if token != "" {
			u += "?pageToken=" + url.QueryEscape(token)
		}
		body, err := get(ctx, svc.Client, u)
		if err != nil {
			return err
		}
		if err := fn(body); err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var next struct {
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &next); err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if next.NextPageToken == "" {
			return nil
		}
		token = next.NextPageToken
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

// resourcePath returns a Compute resource URL from "projects/" on, so a
// reference and a self link name the same resource whatever their host or
// API version.
func resourcePath(u string) string {
	if i := strings.Index(u, "projects/"); i >= 0 {
		return u[i:]
	}
	return u
}
