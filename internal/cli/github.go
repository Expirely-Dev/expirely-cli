package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/expirely-dev/expirely-cli/internal/scan"
	"github.com/expirely-dev/expirely-cli/internal/ui"
)

// maxSummaryRows bounds the job summary table, far below GitHub's 1 MiB
// limit for a step summary; the JSON report keeps every result.
const maxSummaryRows = 200

// maxAnnotations is how many annotations of each kind GitHub shows for a
// step; expirely writes no more than that, most urgent first.
const maxAnnotations = 10

// github reports r to GitHub Actions when expirely runs in a workflow
// (GITHUB_ACTIONS=true): it appends a job summary of every certificate that
// needs attention to the GITHUB_STEP_SUMMARY file, and writes an error or
// warning annotation per certificate on stderr, which the runner reads as
// workflow commands. It looks at every result, whatever --status, --fields
// and --limit show, as the exit code does. EXPIRELY_GITHUB=0 turns it off.
func (c *command) github(r report) {
	if c.Getenv == nil || c.Getenv("GITHUB_ACTIONS") != "true" || c.Getenv("EXPIRELY_GITHUB") == "0" {
		return
	}
	findings := byUrgency(r.all)
	if path := c.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if err := appendFile(path, githubSummary(r, findings)); err != nil {
			fmt.Fprintf(c.Stderr, "::warning title=expirely::%s\n", workflowData("could not write the job summary: "+err.Error()))
		}
	}
	writeAnnotations(c.Stderr, r, findings)
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, text); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// needsAttention reports whether f is expired, expiring or unreadable.
func needsAttention(f scan.Finding) bool { return f.Status != scan.StatusOK }

// githubSummary is the Markdown job summary of r: a table of every result
// that needs attention, most urgent first, or one line naming the
// certificate that expires first when all are ok.
func githubSummary(r report, findings []scan.Finding) string {
	var b strings.Builder
	var attention []scan.Finding
	for _, f := range findings {
		if needsAttention(f) {
			attention = append(attention, f)
		}
	}

	switch n := len(attention); {
	case n == 1:
		b.WriteString("## expirely: 1 certificate needs attention\n\n")
	case n > 1:
		fmt.Fprintf(&b, "## expirely: %d certificates need attention\n\n", n)
	case len(r.Unreadable) > 0:
		b.WriteString("## expirely: some places could not be read\n\n")
	case len(findings) == 0:
		b.WriteString("## expirely: no certificates found\n\n")
	case len(findings) == 1:
		b.WriteString("## expirely: the certificate is ok\n\n")
	default:
		fmt.Fprintf(&b, "## expirely: all %d certificates are ok\n\n", len(findings))
	}

	if len(attention) > 0 {
		b.WriteString("| Status | Target | Expires | Days left | Details |\n| --- | --- | --- | --- | --- |\n")
		for i, f := range attention {
			if i == maxSummaryRows {
				fmt.Fprintf(&b, "\n%d more are in the JSON report.\n", len(attention)-maxSummaryRows)
				break
			}
			days := ""
			if f.DaysLeft != nil {
				days = strconv.Itoa(*f.DaysLeft)
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
				f.Status, strings.ReplaceAll(markdownCell(displayTarget(f.Target)), "`", ""), date(f), days, markdownCell(detail(f)))
		}
		b.WriteString("\n")
	} else if len(findings) > 0 {
		first := findings[0]
		for _, f := range findings {
			if f.DaysLeft != nil && (first.DaysLeft == nil || *f.DaysLeft < *first.DaysLeft) {
				first = f
			}
		}
		fmt.Fprintf(&b, "`%s` expires first, in %s (%s).\n\n", strings.ReplaceAll(markdownCell(displayTarget(first.Target)), "`", ""), when(first), date(first))
	}

	if len(r.Unreadable) > 0 {
		fmt.Fprintf(&b, "Could not read %s; certificates kept there are missing from this report.\n\n", markdownCell(strings.Join(r.Unreadable, ", ")))
	}
	fmt.Fprintf(&b, "Checked %d: %d ok, %d expiring, %d expired, %d unreadable. warn-days %d, expirely %s.\n",
		r.Summary["total"], r.Summary[string(scan.StatusOK)], r.Summary[string(scan.StatusExpiring)],
		r.Summary[string(scan.StatusExpired)], r.Summary[string(scan.StatusError)], r.WarnDays, version())
	return b.String()
}

// detail says why a result needs attention beyond its status: the reason
// it could not be read, a trust problem, or where a cloud certificate lives
// and how many resources use it.
func detail(f scan.Finding) string {
	switch {
	case f.Error != nil:
		return f.Error.Reason
	case f.TrustIssue != nil && *f.TrustIssue != scan.TrustExpired:
		return "not trusted: " + trustWords[*f.TrustIssue]
	case f.ACM != nil:
		return "ACM " + f.ACM.Region + ", " + resourceCount(len(f.ACM.InUseBy))
	case f.GCP != nil:
		return "Google Cloud " + f.GCP.Location + ", " + resourceCount(len(f.GCP.InUseBy))
	}
	return ""
}

func resourceCount(n int) string {
	switch n {
	case 0:
		return "not in use"
	case 1:
		return "in use by 1 resource"
	}
	return "in use by " + strconv.Itoa(n) + " resources"
}

// writeAnnotations writes one workflow command per result that needs
// attention, most urgent first: an error for an expired or unreadable
// certificate and a warning for an expiring one, up to maxAnnotations of
// each kind, then a notice counting the rest.
func writeAnnotations(w io.Writer, r report, findings []scan.Finding) {
	shown := map[string]int{}
	hidden := 0
	for _, f := range findings {
		if !needsAttention(f) {
			continue
		}
		target := displayTarget(f.Target)
		kind, title, message := "error", "Certificate expired: "+target, target+" expired "+when(f)+", on "+date(f)+"."
		switch f.Status {
		case scan.StatusExpiring:
			kind, title, message = "warning", "Certificate expiring: "+target, target+" expires in "+when(f)+", on "+date(f)+"."
		case scan.StatusError:
			title, message = "Certificate not read: "+target, target+" could not be read: "+when(f)+"."
		}
		if shown[kind] == maxAnnotations {
			hidden++
			continue
		}
		shown[kind]++
		fmt.Fprintf(w, "::%s title=%s::%s\n", kind, workflowProperty(title), workflowData(message))
	}
	if len(r.Unreadable) > 0 {
		places := strings.Join(r.Unreadable, ", ")
		fmt.Fprintf(w, "::error title=%s::%s\n", workflowProperty("Not read: "+places),
			workflowData("Could not read "+places+"; certificates kept there are missing from this report."))
	}
	if hidden > 0 {
		fmt.Fprintf(w, "::notice title=expirely::%s\n",
			workflowData(strconv.Itoa(hidden)+" more certificates need attention; GitHub shows "+strconv.Itoa(maxAnnotations)+" annotations of each kind, and the job summary lists them all."))
	}
}

// markdownCell makes text safe inside a Markdown table cell: one line, no
// control characters, no HTML and no column breaks.
func markdownCell(s string) string {
	s = ui.Clean(strings.Join(strings.Fields(s), " "))
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", `\|`).Replace(s)
}

// workflowData makes the message of a workflow command one line with %
// escaped, so text from a certificate or a remote error cannot end the
// command or start another.
func workflowData(s string) string {
	return strings.ReplaceAll(ui.Clean(strings.Join(strings.Fields(s), " ")), "%", "%25")
}

// workflowProperty escapes a workflow command property such as title.
func workflowProperty(s string) string {
	return strings.NewReplacer(":", "%3A", ",", "%2C").Replace(workflowData(s))
}
