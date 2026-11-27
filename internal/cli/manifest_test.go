package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/revocation"
	"github.com/expirely-dev/expirely-cli/internal/tls/scan"
)

// manifest describes the public contract of expirely as data: every
// command with its flags, every exit code, error code, status and result
// field. It is written to manifest.json at the repository root, and the
// documentation site renders its reference tables from the copy of the
// release it documents, so those tables cannot differ from the binary.
type manifest struct {
	ManifestVersion    int               `json:"manifest_version"`
	Name               string            `json:"name"`
	SchemaVersion      int               `json:"schema_version"`
	Commands           []manifestCommand `json:"commands"`
	ExitCodes          []manifestExit    `json:"exit_codes"`
	ErrorCodes         []manifestError   `json:"error_codes"`
	ResultErrorCodes   []manifestError   `json:"result_error_codes"`
	Statuses           []manifestStatus  `json:"statuses"`
	AgentStatuses      []string          `json:"agent_default_statuses"`
	ResultFields       []string          `json:"result_fields"`
	Kinds              []string          `json:"kinds"`
	Sources            []string          `json:"sources"`
	TrustIssues        []string          `json:"trust_issues"`
	RevocationStatuses []string          `json:"revocation_statuses"`
}

type manifestCommand struct {
	Name    string         `json:"name"`
	Summary string         `json:"summary"`
	Usage   string         `json:"usage"`
	Flags   []manifestFlag `json:"flags"`
}

// manifestFlag is one flag. Type is boolean, integer, duration, string or
// list; a list takes commas, a repeated flag, or both. Value is the
// placeholder the help shows for the flag's value, and Default is nil for a
// flag whose default the help describes in words.
type manifestFlag struct {
	Name        string  `json:"name"`
	Short       *string `json:"short"`
	Type        string  `json:"type"`
	Value       *string `json:"value"`
	Default     *string `json:"default"`
	Description string  `json:"description"`
}

type manifestExit struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

type manifestError struct {
	Code        string  `json:"code"`
	Exit        *int    `json:"exit"`
	Cause       *string `json:"cause"`
	Remediation string  `json:"remediation"`
}

type manifestStatus struct {
	Status string `json:"status"`
	Exit   int    `json:"exit"`
}

// helpFlag matches the first line of a flag in a help text: an optional
// short form, the long name, an optional value placeholder and the
// description, which continues on the lines indented under it.
var helpFlag = regexp.MustCompile(`^(?:  -(\w), |      )--([a-z][a-z-]*)(?: ([A-Z]+))?  +(\S.*)$`)

// helpFlags reads the flags a help text documents, in its order.
func helpFlags(usage string) []manifestFlag {
	var flags []manifestFlag
	inFlag := false
	for line := range strings.SplitSeq(usage, "\n") {
		if m := helpFlag.FindStringSubmatch(line); m != nil {
			f := manifestFlag{Name: m[2], Description: m[4]}
			if m[1] != "" {
				f.Short = &m[1]
			}
			if m[3] != "" {
				f.Value = &m[3]
			}
			flags = append(flags, f)
			inFlag = true
			continue
		}
		if inFlag && strings.HasPrefix(line, strings.Repeat(" ", 26)) {
			flags[len(flags)-1].Description += " " + strings.TrimSpace(line)
			continue
		}
		inFlag = false
	}
	return flags
}

// commandOf joins what the help of a command says about its flags with what
// its flag set defines, and fails the test when they disagree: a flag the
// command parses and the help leaves out, or one the help documents and
// the command does not parse.
func commandOf(t *testing.T, name, usage string, fs *flag.FlagSet) manifestCommand {
	t.Helper()
	fs.Bool("json", false, "")
	summary, _, _ := strings.Cut(usage, "\n\n")
	cmd := manifestCommand{Name: name, Summary: strings.Join(strings.Fields(summary), " "), Usage: usage, Flags: helpFlags(usage)}

	documented := map[string]bool{}
	for i, f := range cmd.Flags {
		documented[f.Name] = true
		if f.Short != nil {
			documented[*f.Short] = true
		}
		if f.Name == "help" {
			cmd.Flags[i].Type = "boolean"
			continue
		}
		def := fs.Lookup(f.Name)
		if def == nil {
			t.Errorf("the help of %s documents --%s, which the command does not parse", name, f.Name)
			continue
		}
		if f.Short != nil && fs.Lookup(*f.Short) == nil {
			t.Errorf("the help of %s documents -%s, which the command does not parse", name, *f.Short)
		}
		cmd.Flags[i].Type = "list"
		if g, ok := def.Value.(flag.Getter); ok {
			switch g.Get().(type) {
			case bool:
				cmd.Flags[i].Type = "boolean"
			case int:
				cmd.Flags[i].Type = "integer"
			case time.Duration:
				cmd.Flags[i].Type = "duration"
			case string:
				cmd.Flags[i].Type = "string"
			}
		}
		if def.DefValue != "" && cmd.Flags[i].Type != "boolean" && cmd.Flags[i].Type != "list" && def.Name != "limit" {
			cmd.Flags[i].Default = &def.DefValue
		}
	}
	fs.VisitAll(func(f *flag.Flag) {
		if !documented[f.Name] {
			t.Errorf("%s parses --%s, which its help does not document", name, f.Name)
		}
	})
	return cmd
}

func buildManifest(t *testing.T) manifest {
	t.Helper()
	rootFlags, _ := newRootFlags()
	awsFlags, _, _, _, _ := newAWSFlags()
	gcpFlags, _, _, _ := newGCPFlags()
	m := manifest{
		ManifestVersion: 1,
		Name:            "expirely",
		SchemaVersion:   schemaVersion,
		Commands: []manifestCommand{
			commandOf(t, "expirely", rootUsage, rootFlags),
			commandOf(t, "expirely tls", tlsUsage, newScanFlags().fs),
			commandOf(t, "expirely tls aws", awsUsage, awsFlags),
			commandOf(t, "expirely tls gcp", gcpUsage, gcpFlags),
		},
		ResultFields:       resultFields,
		Kinds:              []string{scan.KindTLSCertificate},
		Sources:            []string{scan.SourceEndpoint, scan.SourceAWSACM, scan.SourceGCP},
		TrustIssues:        []string{scan.TrustExpired, scan.TrustSelfSigned, scan.TrustUnknownAuthority, scan.TrustNameMismatch, scan.TrustInvalid},
		RevocationStatuses: []string{revocation.StatusGood, revocation.StatusRevoked, revocation.StatusUnknown},
	}

	for code, meaning := range exitMeanings {
		m.ExitCodes = append(m.ExitCodes, manifestExit{Code: code, Meaning: meaning})
	}
	slices.SortFunc(m.ExitCodes, func(a, b manifestExit) int { return a.Code - b.Code })

	for code, exit := range errorCodes {
		cause, ok := causes[code]
		if !ok || remediations[code] == "" {
			t.Errorf("error code %q lacks a cause or a remediation", code)
		}
		if _, ok := exitMeanings[exit]; !ok {
			t.Errorf("error code %q exits %d, which has no meaning in exitMeanings", code, exit)
		}
		m.ErrorCodes = append(m.ErrorCodes, manifestError{Code: code, Exit: &exit, Cause: &cause, Remediation: remediations[code]})
	}
	for code := range causes {
		if _, ok := errorCodes[code]; !ok {
			t.Errorf("causes has %q, which is not an error code", code)
		}
	}
	for code, remediation := range scan.Remediations {
		m.ResultErrorCodes = append(m.ResultErrorCodes, manifestError{Code: code, Remediation: remediation})
	}
	byCode := func(a, b manifestError) int { return strings.Compare(a.Code, b.Code) }
	slices.SortFunc(m.ErrorCodes, byCode)
	slices.SortFunc(m.ResultErrorCodes, byCode)

	for _, s := range statusOrder {
		m.Statuses = append(m.Statuses, manifestStatus{Status: string(s), Exit: exitCode([]scan.Finding{{Status: s}})})
	}
	for _, s := range agentStatuses {
		m.AgentStatuses = append(m.AgentStatuses, string(s))
	}
	return m
}

// TestManifest keeps manifest.json equal to what the code defines. After a
// change to a flag, a help text, a code or a status, regenerate it with
// just manifest and read the diff: it is the change to the public contract.
func TestManifest(t *testing.T) {
	var got bytes.Buffer
	enc := json.NewEncoder(&got)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(buildManifest(t)); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join("..", "..", "manifest.json")
	if *update {
		if err := os.WriteFile(path, got.Bytes(), 0o644); err != nil { //nolint:gosec // G306: a file committed to the repository, read by everyone.
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed path.
	if err != nil {
		t.Fatalf("read the manifest: %v (run just manifest)", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("manifest.json differs from what the code defines; run just manifest and read the diff")
	}
}

func TestHelpFlagsReadsEveryFlagLine(t *testing.T) {
	for name, usage := range map[string]string{"expirely": rootUsage, "tls": tlsUsage, "tls aws": awsUsage, "tls gcp": gcpUsage} {
		lines := 0
		for line := range strings.SplitSeq(usage, "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, " "), "-") {
				lines++
			}
		}
		if got := len(helpFlags(usage)); got != lines {
			t.Errorf("the help of %s has %d lines that start with a flag, and helpFlags read %d", name, lines, got)
		}
	}
}
