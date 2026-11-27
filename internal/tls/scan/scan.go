// Package scan turns probe results into findings: for each target, whether
// the certificate chain it serves is ok, expiring within a warning window,
// expired, of unknown end date, or could not be read.
package scan

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/probe"
	"github.com/expirely-dev/expirely-cli/internal/tls/revocation"
	"github.com/expirely-dev/expirely-cli/internal/tls/target"
)

// Status is the expiry state of one target.
type Status string

// Statuses, from most to least urgent.
const (
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked"
	StatusExpiring Status = "expiring"
	StatusError    Status = "error"
	StatusUnknown  Status = "unknown"
	StatusOK       Status = "ok"
)

// KindTLSCertificate is the kind of every finding this package builds.
const KindTLSCertificate = "tls_certificate"

// Sources of a finding: where its certificate was read. They are part of
// the public JSON contract.
const (
	SourceEndpoint = "endpoint"
	SourceAWSACM   = "aws_acm"
	SourceGCP      = "gcp"
)

// Codes of a Finding.Error. They are part of the public JSON contract.
const (
	CodeDialFailed      = "dial_failed"
	CodeHandshakeFailed = "handshake_failed"
)

// Cert is the part of a certificate a finding reports.
type Cert struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
}

// FindingError is why a target could not be read. Reason says it in a few
// words for a person; Message is the full error; Remediation says what
// resolves it, as facts rather than instructions.
type FindingError struct {
	Code        string `json:"code"`
	Reason      string `json:"reason"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// Remediations says, for each result error code, what resolves it.
var Remediations = map[string]string{
	CodeDialFailed:      "A wrong host or port, a host that is down, or a firewall between this network and the host causes this; reason says which.",
	CodeHandshakeFailed: "The port accepted a connection but did not complete TLS; it may serve plain HTTP, need another port or reject this client; reason says which.",
}

// Finding is the result for one resource. Kind, Source, Target, Status,
// DaysLeft, ExpiresAt and Error are common to every kind of resource; TLS
// holds what only a TLS certificate has, and ACM and GCP what a cloud
// provider says about it. When Status is StatusError, Error is set and the
// expiry and TLS fields are nil; otherwise Error is nil. When Status is
// StatusUnknown, the resource exists but its end date could not be read, so
// DaysLeft and ExpiresAt are nil. When Status is StatusRevoked, the
// resource is not expired but its CA or provider revoked it; DaysLeft and
// ExpiresAt still give its end date.
type Finding struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target"`
	Status Status `json:"status"`
	// DaysLeft counts whole days until the first certificate in the chain
	// expires; it is negative once that certificate has expired.
	DaysLeft *int `json:"days_left"`
	// ExpiresAt is when the first certificate in the chain expires, which
	// may be an intermediate rather than the leaf.
	ExpiresAt *time.Time    `json:"expires_at"`
	Error     *FindingError `json:"error"`
	TLS       TLSInfo       `json:"tls"`
	// ACM describes a certificate read from AWS Certificate Manager rather
	// than from a handshake; it is absent for other sources.
	ACM *ACMInfo `json:"acm,omitempty"`
	// GCP describes a certificate read from a Google Cloud project; it is
	// absent for other sources.
	GCP *GCPInfo `json:"gcp,omitempty"`
}

// TLSInfo is what a handshake reveals about a certificate chain. Every field
// is nil when the chain was not read, as on error or for a certificate a
// cloud provider lists.
type TLSInfo struct {
	Trusted *bool `json:"trusted"`
	// TrustIssue names why the chain does not verify, one of the Trust
	// constants; it is nil when the chain verifies or was not read.
	TrustIssue  *string `json:"trust_issue"`
	VerifyError *string `json:"verify_error"`
	// Revocation is whether the leaf is revoked, read from its CA's CRL;
	// it is nil when revocation was not checked.
	Revocation *Revocation `json:"revocation"`
	Leaf       *Cert       `json:"leaf"`
	// Chain is every certificate the server sent, leaf first. Reports
	// leave it out unless asked for, since it is most of their size.
	Chain []Cert `json:"chain,omitempty"`
}

// GCPInfo is what Google Cloud says about one of a project's
// certificates. Source is "compute" for a Compute SSL certificate and
// "certificate_manager" for one in Certificate Manager. Managed is true for
// a certificate Google renews. State is Google's provisioning state of a
// managed certificate, such as ACTIVE or PROVISIONING; it is nil for a
// self-managed one.
type GCPInfo struct {
	Name     string   `json:"name"`
	Location string   `json:"location"`
	Source   string   `json:"source"`
	Managed  bool     `json:"managed"`
	State    *string  `json:"state"`
	InUseBy  []string `json:"in_use_by"`
}

// ACMInfo is what ACM says about one of its certificates. Region is the
// region that holds it. Imported is true for a certificate ACM never
// renews.
type ACMInfo struct {
	ARN                string `json:"arn"`
	Region             string `json:"region"`
	Type               string `json:"type"`
	Imported           bool   `json:"imported"`
	Status             string `json:"status"`
	RenewalEligibility string `json:"renewal_eligibility"`
	// RenewalStatus is the state of ACM's managed renewal, such as
	// PENDING_AUTO_RENEWAL, PENDING_VALIDATION, SUCCESS or FAILED; it is
	// nil when ACM has started none.
	RenewalStatus *string  `json:"renewal_status"`
	InUseBy       []string `json:"in_use_by"`
}

// Revocation is what a CRL says about a leaf. Status is one of the
// revocation package's statuses; Reason says why it is unknown or when the
// leaf was revoked, and is nil for a good one.
type Revocation struct {
	Status string  `json:"status"`
	Reason *string `json:"reason"`
}

// RevocationChecker tells whether leaf, issued by issuer, is revoked. issuer
// is nil when the served chain holds no certificate that signed leaf.
type RevocationChecker interface {
	Check(ctx context.Context, leaf, issuer *x509.Certificate) revocation.Result
}

// Prober reads the certificate chain of a target.
type Prober interface {
	Probe(ctx context.Context, t target.Target) (probe.Result, error)
}

// Options control a scan.
type Options struct {
	// Warn is how close to expiry a certificate becomes StatusExpiring.
	Warn time.Duration
	// Timeout bounds each target's dial and handshake.
	Timeout time.Duration
	// Now is the time findings are computed at.
	Now time.Time
	// Concurrency is the most targets probed at once; values below 1 mean 1.
	Concurrency int
	// Progress, when set, is called once as each target finishes, from the
	// goroutine that probed it, so it must be safe for concurrent use.
	Progress func()
	// Revocation, when set, checks each chain read against its CA's CRL,
	// within its own Timeout after the handshake. It is called from the
	// goroutines that probe, so it must be safe for concurrent use.
	Revocation RevocationChecker
}

// Scan probes the targets, at most opts.Concurrency at a time, and returns
// one finding per target in the order of targets. A target that cannot be
// read becomes a StatusError finding. Once ctx is done, Scan starts no
// more probes and returns ctx's error with no findings. Every goroutine
// Scan starts has returned when Scan returns.
func Scan(ctx context.Context, p Prober, targets []target.Target, opts Options) ([]Finding, error) {
	findings := make([]Finding, len(targets))
	sem := make(chan struct{}, max(opts.Concurrency, 1))
	var wg sync.WaitGroup
admit:
	for i, t := range targets {
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
			findings[i] = scanOne(ctx, p, t, opts)
			if opts.Progress != nil {
				opts.Progress()
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func scanOne(ctx context.Context, p Prober, t target.Target, opts Options) Finding {
	probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	r, err := p.Probe(probeCtx, t)
	if err != nil {
		return errorFinding(t, err)
	}
	f := Classify(r, opts.Now, opts.Warn)
	if opts.Revocation != nil {
		res := revocation.Result{Status: revocation.StatusUnknown, Reason: untrustedChain}
		if r.VerifyError == nil {
			checkCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
			res = opts.Revocation.Check(checkCtx, r.Chain[0], issuerOf(r.Chain))
		}
		f.TLS.Revocation = &Revocation{Status: res.Status}
		if res.Reason != "" {
			f.TLS.Revocation.Reason = &res.Reason
		}
		if res.Status == revocation.StatusRevoked && f.Status != StatusExpired {
			f.Status = StatusRevoked
		}
	}
	return f
}

// untrustedChain is why revocation is unknown for a chain that does not
// verify: the CRL URL in such a certificate was written by whoever serves
// it, so fetching it would let a scanned host choose where expirely
// connects.
const untrustedChain = "the chain is not trusted, so the CRL its certificate names was not fetched"

// issuerOf returns the certificate in chain that signed its leaf, or nil
// when the server did not send it.
func issuerOf(chain []*x509.Certificate) *x509.Certificate {
	for _, c := range chain[1:] {
		if chain[0].CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

// Expiry returns the finding for a certificate known by its end date
// alone, as a cloud provider lists it, read from source: notAfter decides
// the status, expired when it is not after now, expiring when it is within
// warn of now, ok otherwise. The TLS fields stay nil.
func Expiry(source, target string, notAfter, now time.Time, warn time.Duration) Finding {
	status := StatusOK
	switch {
	case !notAfter.After(now):
		status = StatusExpired
	case notAfter.Sub(now) < warn:
		status = StatusExpiring
	}
	days := daysLeft(notAfter.Sub(now))
	expires := notAfter.UTC()
	return Finding{Kind: KindTLSCertificate, Source: source, Target: target, Status: status, DaysLeft: &days, ExpiresAt: &expires}
}

// Unknown returns the finding for a certificate read from source that has
// no end date, such as one a provider has not issued yet. Its expiry and
// TLS fields stay nil.
func Unknown(source, target string) Finding {
	return Finding{Kind: KindTLSCertificate, Source: source, Target: target, Status: StatusUnknown}
}

// Classify computes the finding for a probe result at now. The chain's
// earliest NotAfter decides the status, as in Expiry. r.Chain must not be
// empty, which a Result returned without error guarantees.
func Classify(r probe.Result, now time.Time, warn time.Duration) Finding {
	chain := make([]Cert, 0, len(r.Chain))
	earliest := r.Chain[0].NotAfter
	for _, c := range r.Chain {
		chain = append(chain, Cert{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			Serial:    hex.EncodeToString(c.SerialNumber.Bytes()),
			NotBefore: c.NotBefore.UTC(),
			NotAfter:  c.NotAfter.UTC(),
			DNSNames:  c.DNSNames,
		})
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}

	f := Expiry(SourceEndpoint, r.Target.String(), earliest, now, warn)
	trusted := r.VerifyError == nil
	f.TLS.Trusted = &trusted
	if r.VerifyError != nil {
		msg := r.VerifyError.Error()
		issue := trustIssue(r.VerifyError, r.Chain[0])
		f.TLS.VerifyError, f.TLS.TrustIssue = &msg, &issue
	}
	f.TLS.Leaf, f.TLS.Chain = &chain[0], chain
	return f
}

func daysLeft(d time.Duration) int {
	days := int(d / (24 * time.Hour))
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days
}

func errorFinding(t target.Target, err error) Finding {
	code := CodeHandshakeFailed
	var pe *probe.Error
	if errors.As(err, &pe) && pe.Op == "dial" {
		code = CodeDialFailed
	}
	return Finding{
		Kind:   KindTLSCertificate,
		Source: SourceEndpoint,
		Target: t.String(),
		Status: StatusError,
		Error:  &FindingError{Code: code, Reason: reason(err), Message: err.Error(), Remediation: Remediations[code]},
	}
}
