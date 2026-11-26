package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func ptr[T any](v T) *T { return &v }

func sampleReport() report {
	expires := func(s string) *time.Time {
		at, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return &at
	}
	findings := []scan.Finding{
		{Target: "example.com:443", Status: scan.StatusOK, DaysLeft: ptr(88), ExpiresAt: expires("2027-02-22T23:53:00Z"), Trusted: ptr(true)},
		{Target: "localhost:1", Status: scan.StatusError, Error: &scan.FindingError{Code: scan.CodeDialFailed, Reason: "connection refused", Message: "dial localhost:1: connection refused"}},
		{Target: "expired.badssl.com:443", Status: scan.StatusExpired, DaysLeft: ptr(-4246), ExpiresAt: expires("2015-04-12T23:59:59Z"), Trusted: ptr(false), TrustIssue: ptr(scan.TrustExpired)},
		{Target: "soon.example.com:8443", Status: scan.StatusExpiring, DaysLeft: ptr(1), ExpiresAt: expires("2026-11-28T10:00:00Z"), Trusted: ptr(true)},
		{Target: "wrong.host.badssl.com:443", Status: scan.StatusOK, DaysLeft: ptr(31), ExpiresAt: expires("2026-12-28T20:02:00Z"), Trusted: ptr(false), TrustIssue: ptr(scan.TrustNameMismatch)},
		{Target: "self-signed.badssl.com:443", Status: scan.StatusOK, DaysLeft: ptr(727), ExpiresAt: expires("2028-11-23T21:00:00Z"), Trusted: ptr(false), TrustIssue: ptr(scan.TrustSelfSigned)},
		{Target: "evil\x1b[2J.example:443", Status: scan.StatusOK, DaysLeft: ptr(0), ExpiresAt: expires("2026-11-27T01:00:00Z"), Trusted: ptr(false), TrustIssue: ptr(scan.TrustUnknownAuthority)},
	}
	return newReport(time.Date(2026, 11, 26, 22, 0, 0, 0, time.UTC), 30, findings)
}

func TestWriteTextGolden(t *testing.T) {
	var got bytes.Buffer
	writeText(&got, ui.Style{}, sampleReport(), 412*time.Millisecond)

	path := filepath.Join("testdata", "text.golden")
	if *update {
		if err := os.WriteFile(path, got.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed golden file path.
	if err != nil {
		t.Fatalf("read golden file: %v (run go test ./internal/cli -run TestWriteTextGolden -update)", err)
	}
	if got.String() != string(want) {
		t.Errorf("text output differs from %s:\n--- got\n%s\n--- want\n%s", path, got.String(), want)
	}
}

func TestWriteTextStyledIsPlainPlusEscapes(t *testing.T) {
	var plain, styled bytes.Buffer
	writeText(&plain, ui.Style{}, sampleReport(), 412*time.Millisecond)
	writeText(&styled, ui.Style{Profile: colorprofile.TrueColor}, sampleReport(), 412*time.Millisecond)

	if !strings.Contains(styled.String(), "\x1b[") {
		t.Fatal("styled output has no escape codes")
	}
	if got := ansi.Strip(styled.String()); got != plain.String() {
		t.Errorf("styled output without escape codes differs from plain:\n--- styled, stripped\n%s\n--- plain\n%s", got, plain.String())
	}
}

func TestWhen(t *testing.T) {
	tests := []struct {
		status scan.Status
		days   int
		want   string
	}{
		{scan.StatusOK, 4246, "4,246 days"},
		{scan.StatusOK, 1, "1 day"},
		{scan.StatusExpiring, 0, "under a day"},
		{scan.StatusExpired, 0, "today"},
		{scan.StatusExpired, -1, "1 day ago"},
		{scan.StatusExpired, -1234567, "1,234,567 days ago"},
	}
	for _, tt := range tests {
		if got := when(scan.Finding{Status: tt.status, DaysLeft: ptr(tt.days)}); got != tt.want {
			t.Errorf("when(%s, %d) = %q, want %q", tt.status, tt.days, got, tt.want)
		}
	}
}

func TestDuration(t *testing.T) {
	tests := map[time.Duration]string{
		300 * time.Microsecond:   "1ms",
		41 * time.Millisecond:    "41ms",
		412 * time.Millisecond:   "412ms",
		1450 * time.Millisecond:  "1.4s",
		12340 * time.Millisecond: "12.3s",
		95 * time.Second:         "1m35s",
	}
	for d, want := range tests {
		if got := duration(d); got != want {
			t.Errorf("duration(%v) = %q, want %q", d, got, want)
		}
	}
}
