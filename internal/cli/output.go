package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/scan"
	"github.com/expirely-dev/expirely-cli/internal/ui"
)

// report is the JSON document a command prints; its field names are part
// of the public contract. Summary counts every result, with their total;
// Matched counts those whose status the view shows, and Truncated is true
// when --limit left some of them out of Results. The counts come before
// Results, so a reader that only sees the start of the output still knows
// what it is missing. Unreadable names the places a cloud command could
// not read, so Results may lack certificates kept there; it is empty for a
// complete report.
type report struct {
	SchemaVersion int            `json:"schema_version"`
	ScannedAt     time.Time      `json:"scanned_at"`
	WarnDays      int            `json:"warn_days"`
	Summary       map[string]int `json:"summary"`
	Filter        reportFilter   `json:"filter"`
	Matched       int            `json:"matched"`
	Truncated     bool           `json:"truncated"`
	Unreadable    []string       `json:"unreadable"`
	Results       []scan.Finding `json:"results"`

	all    []scan.Finding
	fields []string
}

// reportFilter says which results the report shows: Status lists the
// statuses shown, most urgent first, and Limit is the --limit value, or
// nil without one.
type reportFilter struct {
	Status []scan.Status `json:"status"`
	Limit  *int          `json:"limit"`
}

// MarshalJSON prints each result with only the --fields keys when some
// were chosen.
func (r report) MarshalJSON() ([]byte, error) {
	type plain report
	if len(r.fields) == 0 {
		return json.Marshal(plain(r))
	}
	projected := make([]projection, len(r.Results))
	for i, f := range r.Results {
		projected[i] = projection{finding: f, fields: r.fields}
	}
	return json.Marshal(struct {
		plain
		Results []projection `json:"results"`
	}{plain(r), projected})
}

// schemaVersion is the version of the JSON report. It changes when a field
// is removed or changes meaning; adding a field keeps it.
const schemaVersion = 1

// newReport builds the report for findings as v shows them: sorted most
// urgent first, the statuses v shows, at most v.limit of them, and without
// certificate chains unless v keeps them. A nil v shows everything.
func newReport(now time.Time, warnDays int, findings []scan.Finding, v *view) report {
	if v == nil {
		v = &view{}
	}
	statuses := v.statuses
	if len(statuses) == 0 {
		statuses = statusOrder
	}
	summary := map[string]int{"total": len(findings)}
	for _, s := range statusOrder {
		summary[string(s)] = 0
	}
	for _, f := range findings {
		summary[string(f.Status)]++
	}

	var shown []scan.Finding
	for _, f := range byUrgency(findings) {
		if slices.Contains(statuses, f.Status) {
			if !v.details {
				f.Chain = nil
			}
			shown = append(shown, f)
		}
	}
	r := report{
		SchemaVersion: schemaVersion,
		ScannedAt:     now.UTC(),
		WarnDays:      warnDays,
		Summary:       summary,
		Filter:        reportFilter{Status: statuses},
		Matched:       len(shown),
		Unreadable:    []string{},
		Results:       shown,
		all:           findings,
		fields:        v.fields,
	}
	if v.limitSet {
		r.Filter.Limit = &v.limit
		if len(shown) > v.limit {
			r.Results, r.Truncated = shown[:v.limit], true
		}
	}
	if r.Results == nil {
		r.Results = []scan.Finding{}
	}
	return r
}

var trustWords = map[string]string{
	scan.TrustSelfSigned:       "self-signed",
	scan.TrustUnknownAuthority: "untrusted issuer",
	scan.TrustNameMismatch:     "wrong name",
	scan.TrustInvalid:          "not trusted",
}

// writeText prints one line per result the report shows, in its order,
// then a summary of every result with the time the work took, and a line
// saying what was left out when a filter or --limit hid any. Cells are
// padded as plain text and styled afterwards, so the plain render and the
// styled render line up the same. Text read from certificates and errors
// passes through ui.Clean.
func writeText(w io.Writer, st ui.Style, r report, elapsed time.Duration) {
	rows := r.Results

	cells := make([][4]string, len(rows))
	var width [4]int
	for i, f := range rows {
		cells[i] = [4]string{statusWord(f.Status), displayTarget(f.Target), when(f), date(f)}
		for c, text := range cells[i] {
			width[c] = max(width[c], len(text))
		}
	}

	var b strings.Builder
	b.WriteString("\n")
	for i, f := range rows {
		noteText, noteWarns := note(f)
		texts := []string{cells[i][0], cells[i][1], cells[i][2], cells[i][3], noteText}
		last := len(texts) - 1
		for last > 0 && texts[last] == "" {
			last--
		}
		b.WriteString(" ")
		for c := 0; c <= last; c++ {
			text := texts[c]
			if c < last {
				text = pad(text, width[c])
			}
			b.WriteString(" ")
			b.WriteString(cellStyle(st, f.Status, c, text, noteWarns))
			if c < last {
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\n  ")
	b.WriteString(summary(st, r))
	b.WriteString(" ")
	b.WriteString(st.Faint("in " + duration(elapsed)))
	b.WriteString("\n")
	if hidden := hiddenNote(r); hidden != "" {
		b.WriteString("  ")
		b.WriteString(st.Faint(hidden))
		b.WriteString("\n")
	}
	fmt.Fprint(w, b.String())
}

// hiddenNote says how many results the report shows out of all of them,
// and with which flags, or is empty when it shows them all.
func hiddenNote(r report) string {
	total := r.Summary["total"]
	if len(r.Results) == total {
		return ""
	}
	var flags []string
	if len(r.Filter.Status) < len(statusOrder) {
		names := make([]string, len(r.Filter.Status))
		for i, s := range r.Filter.Status {
			names[i] = string(s)
		}
		flags = append(flags, "--status "+strings.Join(names, ","))
	}
	if r.Truncated {
		flags = append(flags, "--limit "+strconv.Itoa(*r.Filter.Limit))
	}
	return "showing " + strconv.Itoa(len(r.Results)) + " of " + strconv.Itoa(total) + " (" + strings.Join(flags, "; ") + ")"
}

// cellStyle styles column c of a row: the status in its color, the target
// in bold, the date faint and the trust note as a remark. Trailing padding
// stays outside the escape codes, so stripping them gives the plain line.
func cellStyle(st ui.Style, s scan.Status, c int, text string, noteWarns bool) string {
	word := strings.TrimRight(text, " ")
	spaces := text[len(word):]
	switch c {
	case 0:
		word = paint(st, s, word)
	case 1:
		word = st.Bold(word)
	case 3:
		word = st.Faint(word)
	case 4:
		if noteWarns {
			word = st.Note(word)
		} else {
			word = st.Faint(word)
		}
	}
	return word + spaces
}

func pad(text string, width int) string {
	return text + strings.Repeat(" ", width-len(text))
}

// displayTarget drops the default port, the way people type a host; JSON
// keeps the full host:port.
func displayTarget(t string) string {
	return ui.Clean(strings.TrimSuffix(t, ":443"))
}

func statusWord(s scan.Status) string {
	if s == scan.StatusError {
		return "failed"
	}
	return string(s)
}

func paint(st ui.Style, s scan.Status, text string) string {
	switch s {
	case scan.StatusExpired, scan.StatusError:
		return st.Bad(text)
	case scan.StatusExpiring:
		return st.Soon(text)
	default:
		return st.Good(text)
	}
}

func days(f scan.Finding) int {
	if f.DaysLeft == nil {
		return 0
	}
	return *f.DaysLeft
}

// when says how long a certificate has left, or how long ago it expired,
// in whole days; for a target that could not be read it gives the reason.
func when(f scan.Finding) string {
	if f.Error != nil {
		return ui.Clean(f.Error.Reason)
	}
	d := days(f)
	if f.Status == scan.StatusExpired {
		switch d {
		case 0:
			return "today"
		case -1:
			return "1 day ago"
		default:
			return thousands(-d) + " days ago"
		}
	}
	switch d {
	case 0:
		return "under a day"
	case 1:
		return "1 day"
	default:
		return thousands(d) + " days"
	}
}

func date(f scan.Finding) string {
	if f.ExpiresAt == nil {
		return ""
	}
	return f.ExpiresAt.Format("Jan 02 2006")
}

// note names a trust problem in words, or for an ACM certificate whether
// it renews itself. An expired chain needs no note: its status already says
// so. warn reports whether the note asks for attention.
func note(f scan.Finding) (text string, warn bool) {
	if f.ACM != nil {
		return acmNote(f.ACM)
	}
	if f.GCP != nil {
		if f.GCP.Managed {
			return "renews itself", false
		}
		return usageNote("self-managed", len(f.GCP.InUseBy))
	}
	if f.TrustIssue == nil {
		return "", false
	}
	return trustWords[*f.TrustIssue], true
}

// acmNote says whether ACM renews a certificate and, when it does not, how
// many resources use it: a certificate nothing uses can only be cleaned up,
// while one in use is what breaks when it expires, so only that one warns.
func acmNote(a *scan.ACMInfo) (string, bool) {
	var renewal string
	switch {
	case a.Imported:
		renewal = "imported"
	case a.RenewalEligibility == "ELIGIBLE":
		return "renews itself", false
	default:
		renewal = "does not renew"
	}
	return usageNote(renewal, len(a.InUseBy))
}

// usageNote joins how a certificate renews with how many resources use it;
// only a certificate in use asks for attention.
func usageNote(renewal string, n int) (string, bool) {
	switch n {
	case 0:
		return renewal + ", not in use", false
	case 1:
		return renewal + ", in use by 1 resource", true
	default:
		return renewal + ", in use by " + strconv.Itoa(n) + " resources", true
	}
}

// inUse orders certificates in use before those nothing uses, within the
// same status; a scanned target is always in use.
func inUse(f scan.Finding) int {
	switch {
	case f.ACM != nil && len(f.ACM.InUseBy) == 0, f.GCP != nil && len(f.GCP.InUseBy) == 0:
		return 1
	default:
		return 0
	}
}

func summary(st ui.Style, r report) string {
	var parts []string
	for _, s := range statusOrder {
		if n := r.Summary[string(s)]; n > 0 {
			parts = append(parts, paint(st, s, strconv.Itoa(n)+" "+statusWord(s)))
		}
	}
	return strings.Join(parts, ", ")
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func duration(d time.Duration) string {
	if d < time.Second {
		return strconv.FormatInt(max(d.Milliseconds(), 1), 10) + "ms"
	}
	if d < time.Minute {
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	}
	return d.Round(time.Second).String()
}
