// Package scan turns probe results into findings: for each target, whether
// the certificate chain it serves is ok, expiring within a warning window,
// expired, or could not be read.
package scan

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bycavii/expirely-cli/internal/probe"
	"github.com/bycavii/expirely-cli/internal/target"
)

// Status is the expiry state of one target.
type Status string

// Statuses, from most to least urgent.
const (
	StatusExpired  Status = "expired"
	StatusExpiring Status = "expiring"
	StatusError    Status = "error"
	StatusOK       Status = "ok"
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

// FindingError is why a target could not be read.
type FindingError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Finding is the result for one target. When Status is StatusError, Error
// is set and every certificate field is nil; otherwise Error is nil.
type Finding struct {
	Target string `json:"target"`
	Status Status `json:"status"`
	// DaysLeft counts whole days until the first certificate in the chain
	// expires; it is negative once that certificate has expired.
	DaysLeft *int `json:"days_left"`
	// ExpiresAt is when the first certificate in the chain expires, which
	// may be an intermediate rather than the leaf.
	ExpiresAt   *time.Time    `json:"expires_at"`
	Trusted     *bool         `json:"trusted"`
	VerifyError *string       `json:"verify_error"`
	Leaf        *Cert         `json:"leaf"`
	Chain       []Cert        `json:"chain"`
	Error       *FindingError `json:"error"`
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
}

// Scan probes each target in order and returns one finding per target, in
// the same order. A target that cannot be read becomes a StatusError
// finding; Scan itself does not fail.
func Scan(ctx context.Context, p Prober, targets []target.Target, opts Options) []Finding {
	findings := make([]Finding, 0, len(targets))
	for _, t := range targets {
		findings = append(findings, scanOne(ctx, p, t, opts))
	}
	return findings
}

func scanOne(ctx context.Context, p Prober, t target.Target, opts Options) Finding {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	r, err := p.Probe(ctx, t)
	if err != nil {
		return errorFinding(t, err)
	}
	return Classify(r, opts.Now, opts.Warn)
}

// Classify computes the finding for a probe result at now. The chain's
// earliest NotAfter decides the status: expired when it is not after now,
// expiring when it is within warn of now, ok otherwise.
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

	left := earliest.Sub(now)
	status := StatusOK
	switch {
	case !earliest.After(now):
		status = StatusExpired
	case left < warn:
		status = StatusExpiring
	}

	days := daysLeft(left)
	expires := earliest.UTC()
	trusted := r.VerifyError == nil
	var verifyErr *string
	if r.VerifyError != nil {
		msg := r.VerifyError.Error()
		verifyErr = &msg
	}
	leaf := chain[0]
	return Finding{
		Target:      r.Target.String(),
		Status:      status,
		DaysLeft:    &days,
		ExpiresAt:   &expires,
		Trusted:     &trusted,
		VerifyError: verifyErr,
		Leaf:        &leaf,
		Chain:       chain,
	}
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
		Target: t.String(),
		Status: StatusError,
		Error:  &FindingError{Code: code, Message: err.Error()},
	}
}
