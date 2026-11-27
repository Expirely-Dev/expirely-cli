package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"slices"
	"strings"

	"github.com/bycavii/expirely-cli/internal/scan"
)

// statusOrder lists the statuses from most to least urgent; results are
// sorted, filtered and counted in this order.
var statusOrder = []scan.Status{scan.StatusExpired, scan.StatusExpiring, scan.StatusError, scan.StatusOK}

// agentStatuses is what a declared agent sees when it passes no --status:
// everything that needs attention, and none of the ok results, which the
// summary still counts.
var agentStatuses = []scan.Status{scan.StatusExpired, scan.StatusExpiring, scan.StatusError}

// resultFields are the keys of a result, in the order the JSON prints
// them; --fields accepts these names. A test keeps them equal to the JSON
// tags of scan.Finding.
var resultFields = []string{"target", "status", "days_left", "expires_at", "trusted", "trust_issue", "verify_error", "leaf", "chain", "error", "acm", "gcp"}

// listFlag collects a flag given as a comma-separated list, repeated, or
// both; empty items are dropped.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for item := range strings.SplitSeq(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*l = append(*l, item)
		}
	}
	return nil
}

// view is how a report shows its results: which statuses, which fields,
// how many, and whether chains are kept. It never changes the summary or
// the exit code, which always cover every result.
type view struct {
	statusFlag listFlag
	fieldsFlag listFlag
	limit      int
	limitSet   bool
	details    bool

	statuses []scan.Status
	fields   []string
}

// viewFlags defines --status, --fields and --limit on fs.
func viewFlags(fs *flag.FlagSet) *view {
	v := &view{}
	fs.Var(&v.statusFlag, "status", "")
	fs.Var(&v.fieldsFlag, "fields", "")
	fs.IntVar(&v.limit, "limit", 0, "")
	return v
}

// resolve checks the flags fs parsed, before any work starts, and settles
// the statuses shown: those --status names, every status for "all", and
// for a declared agent that names none, agentStatuses.
func (v *view) resolve(c *command, fs *flag.FlagSet) *Error {
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "limit" {
			v.limitSet = true
		}
	})
	if v.limitSet && v.limit < 1 {
		return failf(CodeInvalidFlag, "--limit must be 1 or more, got %d", v.limit)
	}
	for _, name := range v.statusFlag {
		if name == "all" {
			v.statuses = statusOrder
			continue
		}
		s := scan.Status(name)
		if !slices.Contains(statusOrder, s) {
			return failf(CodeInvalidFlag, "unknown status %q in --status; valid: expired, expiring, error, ok, all", name)
		}
		if !slices.Contains(v.statuses, s) {
			v.statuses = append(v.statuses, s)
		}
	}
	switch {
	case len(v.statusFlag) > 0:
	case c.agent.Declared:
		v.statuses = agentStatuses
	default:
		v.statuses = statusOrder
	}
	v.statuses = sortedStatuses(v.statuses)

	for _, name := range v.fieldsFlag {
		if !slices.Contains(resultFields, name) {
			return failf(CodeInvalidFlag, "unknown field %q in --fields; valid: %s", name, strings.Join(resultFields, ", "))
		}
	}
	if len(v.fieldsFlag) > 0 && !c.json {
		return failf(CodeInvalidFlag, "--fields selects JSON fields, and this run prints text; --json, or a stdout that is not a terminal, prints JSON")
	}
	if len(v.fieldsFlag) > 0 {
		v.fields = []string{"target"}
		for _, f := range resultFields {
			if f != "target" && slices.Contains(v.fieldsFlag, f) {
				v.fields = append(v.fields, f)
			}
		}
		if slices.Contains(v.fields, "chain") {
			v.details = true
		}
	}
	return nil
}

func sortedStatuses(s []scan.Status) []scan.Status {
	out := slices.Clone(s)
	slices.SortFunc(out, func(a, b scan.Status) int { return cmp.Compare(rank(a), rank(b)) })
	return out
}

func rank(s scan.Status) int { return slices.Index(statusOrder, s) }

// byUrgency sorts findings most urgent first: by status, then a
// certificate in use before one nothing uses, then fewest days left with
// unknown days last, then in the order they came.
func byUrgency(findings []scan.Finding) []scan.Finding {
	out := slices.Clone(findings)
	slices.SortStableFunc(out, func(a, b scan.Finding) int {
		if c := cmp.Compare(rank(a.Status), rank(b.Status)); c != 0 {
			return c
		}
		if c := cmp.Compare(inUse(a), inUse(b)); c != 0 {
			return c
		}
		switch {
		case a.DaysLeft == nil && b.DaysLeft == nil:
			return 0
		case a.DaysLeft == nil:
			return 1
		case b.DaysLeft == nil:
			return -1
		}
		return cmp.Compare(*a.DaysLeft, *b.DaysLeft)
	})
	return out
}

// projection is a result with only the chosen fields, in schema order. A
// chosen field the result has no value for is null.
type projection struct {
	finding scan.Finding
	fields  []string
}

func (p projection) MarshalJSON() ([]byte, error) {
	full, err := json.Marshal(p.finding)
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(full, &values); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range p.fields {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(f)
		b.Write(key)
		b.WriteByte(':')
		if v, ok := values[f]; ok {
			b.Write(v)
		} else {
			b.WriteString("null")
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
