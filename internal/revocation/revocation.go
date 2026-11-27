// Package revocation checks whether a certificate is revoked, read from the
// certificate revocation list (CRL) its CA publishes. It only reads: it
// fetches each CRL over HTTP, verifies the CRL's signature against the
// certificate's issuer, and looks up the certificate's serial number.
package revocation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Statuses of a Result. They are part of the public JSON contract.
const (
	StatusGood    = "good"
	StatusRevoked = "revoked"
	StatusUnknown = "unknown"
)

// DefaultMaxSize is the largest CRL a Checker reads when MaxSize is zero.
const DefaultMaxSize = 10 << 20

// Result is the revocation state of one certificate. Reason says why the
// state is unknown, or when a revoked certificate was revoked; it is empty
// for a good one.
type Result struct {
	Status string
	Reason string
}

// Checker fetches CRLs and checks certificates against them. Each CRL URL is
// fetched at most once, and every check that names it shares the outcome,
// so a Checker serves one run. Its methods are safe for concurrent use.
type Checker struct {
	// Client fetches CRLs; nil means a client that follows redirects only
	// within the same host. Each fetch is bounded by the context of the
	// check that starts it.
	Client *http.Client
	// MaxSize is the largest CRL read, in bytes; zero means DefaultMaxSize.
	MaxSize int64
	// Now is the time a CRL's NextUpdate is compared with; nil means
	// time.Now.
	Now func() time.Time

	mu    sync.Mutex
	lists map[string]func() (*x509.RevocationList, error)
}

// Check reports whether leaf, issued by issuer, is revoked. It reads the
// first http or https URL in leaf's CRL distribution points. Every failure
// to reach a verdict, such as no CRL URL, a fetch that fails, a CRL over
// MaxSize, a CRL whose signature does not verify against issuer or one past
// its NextUpdate, is StatusUnknown with the reason.
func (c *Checker) Check(ctx context.Context, leaf, issuer *x509.Certificate) Result {
	url := crlURL(leaf)
	if url == "" {
		return unknown("the certificate names no CRL")
	}
	if issuer == nil {
		return unknown("the server sent no issuer certificate to verify the CRL with")
	}
	list, err := c.list(ctx, url)
	if err != nil {
		return unknown(err.Error())
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return unknown(fmt.Sprintf("the CRL at %s is not signed by the certificate's issuer: %v", url, err))
	}
	if now := c.now(); !list.NextUpdate.IsZero() && now.After(list.NextUpdate) {
		return unknown(fmt.Sprintf("the CRL at %s is out of date since %s", url, list.NextUpdate.UTC().Format(time.RFC3339)))
	}
	for _, e := range list.RevokedCertificateEntries {
		if e.SerialNumber != nil && e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return Result{Status: StatusRevoked, Reason: "revoked on " + e.RevocationTime.UTC().Format(time.RFC3339)}
		}
	}
	return Result{Status: StatusGood}
}

func unknown(reason string) Result { return Result{Status: StatusUnknown, Reason: reason} }

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// list returns the CRL at url, fetching it once. The first check that asks
// for url fetches it with its own context; later ones wait for that fetch.
func (c *Checker) list(ctx context.Context, url string) (*x509.RevocationList, error) {
	c.mu.Lock()
	if c.lists == nil {
		c.lists = make(map[string]func() (*x509.RevocationList, error))
	}
	get, ok := c.lists[url]
	if !ok {
		get = sync.OnceValues(func() (*x509.RevocationList, error) { return c.fetch(ctx, url) })
		c.lists[url] = get
	}
	c.mu.Unlock()
	return get()
}

func (c *Checker) fetch(ctx context.Context, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("the CRL URL %s is not valid: %w", url, err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch the CRL at %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch the CRL at %s: %s", url, resp.Status)
	}
	limit := c.MaxSize
	if limit <= 0 {
		limit = DefaultMaxSize
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read the CRL at %s: %w", url, err)
	}
	if int64(len(der)) > limit {
		return nil, fmt.Errorf("the CRL at %s is over %d bytes", url, limit)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse the CRL at %s: %w", url, err)
	}
	return list, nil
}

// errOtherHost stops a redirect that leaves the CRL's host.
var errOtherHost = errors.New("redirect to another host")

func (c *Checker) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{CheckRedirect: SameHost}
}

// SameHost is an http.Client CheckRedirect that follows at most five
// redirects and none to a host other than the first request's.
func SameHost(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("%w: %s", errOtherHost, req.URL.Host)
	}
	return nil
}

func crlURL(cert *x509.Certificate) string {
	for _, u := range cert.CRLDistributionPoints {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return u
		}
	}
	return ""
}
