package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/bycavii/expirely-cli/internal/scan"
)

// report is the JSON document a scan prints; its field names are part of
// the public contract.
type report struct {
	ScannedAt time.Time      `json:"scanned_at"`
	WarnDays  int            `json:"warn_days"`
	Summary   map[string]int `json:"summary"`
	Results   []scan.Finding `json:"results"`
}

func newReport(now time.Time, warnDays int, findings []scan.Finding) report {
	summary := map[string]int{
		string(scan.StatusOK):       0,
		string(scan.StatusExpiring): 0,
		string(scan.StatusExpired):  0,
		string(scan.StatusError):    0,
	}
	for _, f := range findings {
		summary[string(f.Status)]++
	}
	return report{ScannedAt: now.UTC(), WarnDays: warnDays, Summary: summary, Results: findings}
}

func fail(s Streams, jsonOut bool, e *Error) int {
	code := errorCodes[e.Code]
	if jsonOut {
		body := map[string]map[string]string{"error": {"message": e.Message, "code": e.Code}}
		if err := json.NewEncoder(s.Stderr).Encode(body); err != nil {
			fmt.Fprintf(s.Stderr, "expirely: %s (%s)\n", e.Message, e.Code)
		}
		return code
	}
	fmt.Fprintf(s.Stderr, "expirely: %s\n", clean(e.Message))
	if code == ExitUsage {
		fmt.Fprintln(s.Stderr, "Run expirely --help to see every flag.")
	}
	return code
}

func writeJSON(s Streams, jsonOut bool, v any) int {
	if err := json.NewEncoder(s.Stdout).Encode(v); err != nil {
		return fail(s, jsonOut, failf(CodeOutputFailed, "write output: %v", err))
	}
	return ExitOK
}

var urgency = map[scan.Status]int{
	scan.StatusExpired:  0,
	scan.StatusExpiring: 1,
	scan.StatusError:    2,
	scan.StatusOK:       3,
}

// writeText prints the findings as a table, most urgent first, then a
// summary line. Values read from certificates and errors pass through clean
// before they reach a terminal.
func writeText(w io.Writer, r report) {
	rows := slices.Clone(r.Results)
	slices.SortStableFunc(rows, func(a, b scan.Finding) int {
		if c := cmp.Compare(urgency[a.Status], urgency[b.Status]); c != 0 {
			return c
		}
		return cmp.Compare(days(a), days(b))
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tSTATUS\tDAYS\tEXPIRES\tTRUSTED\tDETAIL")
	for _, f := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			clean(f.Target), f.Status, daysText(f), expiresText(f), trustedText(f), clean(detail(f)))
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\n%d targets: %d expired, %d expiring, %d unreadable, %d ok\n",
		len(r.Results), r.Summary[string(scan.StatusExpired)], r.Summary[string(scan.StatusExpiring)],
		r.Summary[string(scan.StatusError)], r.Summary[string(scan.StatusOK)])
}

func days(f scan.Finding) int {
	if f.DaysLeft == nil {
		return 0
	}
	return *f.DaysLeft
}

func daysText(f scan.Finding) string {
	if f.DaysLeft == nil {
		return "unknown"
	}
	return strconv.Itoa(*f.DaysLeft)
}

func expiresText(f scan.Finding) string {
	if f.ExpiresAt == nil {
		return "unknown"
	}
	return f.ExpiresAt.Format("2006-01-02 15:04 UTC")
}

func trustedText(f scan.Finding) string {
	switch {
	case f.Trusted == nil:
		return "unknown"
	case *f.Trusted:
		return "yes"
	default:
		return "no"
	}
}

func detail(f scan.Finding) string {
	if f.Error != nil {
		return f.Error.Message
	}
	if f.Leaf != nil {
		return "issuer " + commonName(f.Leaf.Issuer)
	}
	return ""
}

// commonName returns the CN of a distinguished name in the form
// x509.Name.String prints, or the whole name when it does not start with CN.
func commonName(dn string) string {
	cn, ok := strings.CutPrefix(dn, "CN=")
	if !ok {
		return dn
	}
	for i := 0; i < len(cn); i++ {
		switch cn[i] {
		case '\\':
			i++
		case ',':
			return cn[:i]
		}
	}
	return cn
}

// clean removes control characters, so text from a certificate or a peer
// cannot move the cursor or recolor the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
