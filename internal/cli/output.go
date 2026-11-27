package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bycavii/expirely-cli/internal/scan"
	"github.com/bycavii/expirely-cli/internal/ui"
)

// report is the JSON document a scan prints; its field names are part of
// the public contract.
type report struct {
	SchemaVersion int            `json:"schema_version"`
	ScannedAt     time.Time      `json:"scanned_at"`
	WarnDays      int            `json:"warn_days"`
	Summary       map[string]int `json:"summary"`
	Results       []scan.Finding `json:"results"`
}

// schemaVersion is the version of the JSON report. It changes when a field
// is removed or changes meaning; adding a field keeps it.
const schemaVersion = 1

// newReport builds the report for findings. Without details, each result
// leaves out its certificate chain and keeps the leaf.
func newReport(now time.Time, warnDays int, findings []scan.Finding, details bool) report {
	if !details {
		findings = slices.Clone(findings)
		for i := range findings {
			findings[i].Chain = nil
		}
	}
	summary := map[string]int{
		string(scan.StatusOK):       0,
		string(scan.StatusExpiring): 0,
		string(scan.StatusExpired):  0,
		string(scan.StatusError):    0,
	}
	for _, f := range findings {
		summary[string(f.Status)]++
	}
	return report{SchemaVersion: schemaVersion, ScannedAt: now.UTC(), WarnDays: warnDays, Summary: summary, Results: findings}
}

// mode is how a run reports: JSON or text, and whether an AI agent is
// reading.
type mode struct {
	json  bool
	agent bool
}

// envelope is the JSON a command error prints on stderr. Usage holds the
// whole help, only for a usage error read by an agent.
type envelope struct {
	Error struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		Remediation string `json:"remediation"`
		Usage       string `json:"usage,omitempty"`
	} `json:"error"`
}

// fail prints e and returns its exit code. In JSON it prints the envelope;
// in text it prints the message and, on the next line, what resolves it.
// A usage error read by an agent also gets the whole help, since an agent
// cannot ask for --help the way a person glances at it.
func fail(s Streams, m mode, e *Error) int {
	code := errorCodes[e.Code]
	withUsage := m.agent && code == ExitUsage
	if m.json {
		var body envelope
		body.Error.Code = e.Code
		body.Error.Message = e.Message
		body.Error.Remediation = remediations[e.Code]
		if withUsage {
			body.Error.Usage = usage
		}
		if err := json.NewEncoder(s.Stderr).Encode(body); err != nil {
			fmt.Fprintf(s.Stderr, "expirely: %s (%s)\n", e.Message, e.Code)
		}
		return code
	}
	fmt.Fprintf(s.Stderr, "expirely: %s\n%s\n", ui.Clean(e.Message), remediations[e.Code])
	if withUsage {
		fmt.Fprintf(s.Stderr, "\n%s", usage)
	}
	return code
}

func writeJSON(s Streams, m mode, v any) int {
	if err := json.NewEncoder(s.Stdout).Encode(v); err != nil {
		return fail(s, m, failf(CodeOutputFailed, "write output: %v", err))
	}
	return ExitOK
}

var urgency = map[scan.Status]int{
	scan.StatusExpired:  0,
	scan.StatusExpiring: 1,
	scan.StatusError:    2,
	scan.StatusOK:       3,
}

var trustWords = map[string]string{
	scan.TrustSelfSigned:       "self-signed",
	scan.TrustUnknownAuthority: "untrusted issuer",
	scan.TrustNameMismatch:     "wrong name",
	scan.TrustInvalid:          "not trusted",
}

// writeText prints one line per target, most urgent first, then a summary
// with the time the scan took. Cells are padded as plain text and styled
// afterwards, so the plain render and the styled render line up the same.
// Text read from certificates and errors passes through ui.Clean.
func writeText(w io.Writer, st ui.Style, r report, elapsed time.Duration) {
	rows := slices.Clone(r.Results)
	slices.SortStableFunc(rows, func(a, b scan.Finding) int {
		if c := cmp.Compare(urgency[a.Status], urgency[b.Status]); c != 0 {
			return c
		}
		if c := cmp.Compare(inUse(a), inUse(b)); c != 0 {
			return c
		}
		return cmp.Compare(days(a), days(b))
	})

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
	fmt.Fprint(w, b.String())
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
	for _, s := range []scan.Status{scan.StatusExpired, scan.StatusExpiring, scan.StatusError, scan.StatusOK} {
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
