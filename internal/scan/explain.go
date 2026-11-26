package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/bycavii/expirely-cli/internal/probe"
)

// Trust issues name why a chain does not verify. They are part of the
// public JSON contract.
const (
	TrustExpired          = "expired"
	TrustSelfSigned       = "self_signed"
	TrustUnknownAuthority = "unknown_authority"
	TrustNameMismatch     = "name_mismatch"
	TrustInvalid          = "invalid"
)

// trustIssue names the reason verifyErr gives for chain not verifying. A
// leaf that signed itself is TrustSelfSigned rather than
// TrustUnknownAuthority; a reason with no name of its own is TrustInvalid.
func trustIssue(verifyErr error, leaf *x509.Certificate) string {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	switch {
	case errors.As(verifyErr, &hostErr):
		return TrustNameMismatch
	case errors.As(verifyErr, &authErr):
		if selfSigned(leaf) {
			return TrustSelfSigned
		}
		return TrustUnknownAuthority
	case errors.As(verifyErr, &invalidErr) && invalidErr.Reason == x509.Expired:
		return TrustExpired
	default:
		return TrustInvalid
	}
}

func selfSigned(c *x509.Certificate) bool {
	return len(c.RawSubject) > 0 &&
		bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// reason says in a few words why a probe failed, for a person reading the
// result; the full error stays in the message. Errors with no short form
// keep the innermost message.
func reason(err error) string {
	var dnsErr *net.DNSError
	var headerErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var netErr net.Error
	switch {
	case errors.Is(err, probe.ErrNoCertificate):
		return "no certificate sent"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "no such host"
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	case errors.As(err, &headerErr):
		return "not a TLS server"
	case errors.As(err, &alertErr):
		return "rejected by the server: " + strings.TrimPrefix(alertErr.Error(), "tls: ")
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed during the handshake"
	default:
		return innermost(err).Error()
	}
}

func innermost(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}
