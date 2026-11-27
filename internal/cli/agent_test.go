package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/expirely-dev/expirely-cli/internal/tls/tlstest"
	"github.com/expirely-dev/expirely-cli/internal/ui"
)

func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDetectAgent(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		terminal bool
		want     agent
	}{
		{name: "nothing set", terminal: true, want: agent{}},
		{name: "override declares an agent", env: map[string]string{"EXPIRELY_AGENT": "1"}, terminal: true, want: agent{Name: "expirely-agent", Declared: true}},
		{name: "override declares a person over every marker", env: map[string]string{"EXPIRELY_AGENT": "false", "AI_AGENT": "goose", "CODEX_SANDBOX": "seatbelt"}, terminal: true, want: agent{}},
		{name: "AI_AGENT names the agent", env: map[string]string{"AI_AGENT": "claude-code", "AGENT": "amp"}, terminal: true, want: agent{Name: "claude-code", Declared: true}},
		{name: "AGENT names the agent", env: map[string]string{"AGENT": "amp"}, terminal: true, want: agent{Name: "amp", Declared: true}},
		{name: "AI_AGENT=0 is not an agent", env: map[string]string{"AI_AGENT": "0"}, terminal: true, want: agent{}},
		{name: "codex under a pseudo-terminal is declared", env: map[string]string{"CODEX_SANDBOX": "seatbelt"}, terminal: true, want: agent{Name: "codex", Declared: true}},
		{name: "gemini is detected, not declared", env: map[string]string{"GEMINI_CLI": "1"}, terminal: true, want: agent{Name: "gemini-cli"}},
		{name: "CLAUDECODE in a terminal may be a person", env: map[string]string{"CLAUDECODE": "1"}, terminal: true, want: agent{}},
		{name: "CLAUDECODE outside a terminal is an agent", env: map[string]string{"CLAUDECODE": "1"}, terminal: false, want: agent{Name: "claude-code"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectAgent(envOf(tt.env), tt.terminal); got != tt.want {
				t.Errorf("detectAgent() = %+v, want %+v", got, tt.want)
			}
		})
	}
	if got := detectAgent(nil, true); got != (agent{}) {
		t.Errorf("detectAgent(nil) = %+v, want no agent", got)
	}
}

func TestRunForAgentsOnATerminal(t *testing.T) {
	ca := tlstest.NewCA(t)
	healthy := fmt.Sprintf("localhost:%d", tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*24*time.Hour))))
	release := make(chan struct{})
	slow := fmt.Sprintf("localhost:%d", tlstest.Serve(t, func(net.Conn) { <-release }))
	t.Cleanup(func() { close(release) })

	tests := []struct {
		name     string
		env      map[string]string
		args     []string
		wantJSON bool
	}{
		{name: "a person gets color and text", env: nil, wantJSON: false},
		{name: "a declared agent gets JSON", env: map[string]string{"AI_AGENT": "goose"}, wantJSON: true},
		{name: "a detected agent gets plain text", env: map[string]string{"GEMINI_CLI": "1"}, wantJSON: false},
		{name: "--json=false wins over a declared agent", env: map[string]string{"AI_AGENT": "goose"}, args: []string{"--json=false"}, wantJSON: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{"tls", "--timeout", "400ms"}, tt.args...), healthy, slow)
			Run(context.Background(), args, Streams{
				Stdin:            strings.NewReader(""),
				Stdout:           &stdout,
				Stderr:           &stderr,
				StdoutIsTerminal: true,
				StderrIsTerminal: true,
				Style:            ui.Style{Profile: colorprofile.TrueColor},
				Getenv:           envOf(tt.env),
			})

			if got := json.Valid(stdout.Bytes()); got != tt.wantJSON {
				t.Errorf("stdout is JSON = %v, want %v:\n%s", got, tt.wantJSON, stdout.String())
			}
			person := tt.env == nil
			if hasEscapes := strings.Contains(stdout.String(), "\x1b["); hasEscapes != person {
				t.Errorf("stdout has escape codes = %v, want %v for a person", hasEscapes, person)
			}
			if spinner := strings.Contains(stderr.String(), "Scanning"); spinner != person {
				t.Errorf("stderr has the spinner = %v, want %v for a person", spinner, person)
			}
		})
	}
}

func TestRunJSONFalseGivesTextOutsideATerminal(t *testing.T) {
	ca := tlstest.NewCA(t)
	port := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*24*time.Hour)))

	_, stdout, _ := run(t, false, "--json=false", fmt.Sprintf("localhost:%d", port))

	if json.Valid([]byte(stdout)) || !strings.Contains(stdout, "1 ok in ") {
		t.Errorf("stdout = %q, want the text output that --json=false asks for", stdout)
	}
}

func TestUsageErrorsGiveAgentsTheWholeHelp(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		terminal  bool
		args      []string
		wantUsage bool
	}{
		{name: "a person gets the short error", terminal: true, args: []string{"--nope"}},
		{name: "a declared agent gets usage in the envelope", env: map[string]string{"AI_AGENT": "goose"}, terminal: true, args: []string{"--nope"}, wantUsage: true},
		{name: "a detected agent gets usage in text", env: map[string]string{"GEMINI_CLI": "1"}, terminal: true, args: []string{"--nope"}, wantUsage: true},
		{name: "an agent with no targets gets usage, not the intro", env: map[string]string{"GEMINI_CLI": "1"}, terminal: true, wantUsage: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), append([]string{"tls"}, tt.args...), Streams{
				Stdin:            strings.NewReader(""),
				Stdout:           &stdout,
				Stderr:           &stderr,
				StdoutIsTerminal: tt.terminal,
				Getenv:           envOf(tt.env),
			})

			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d", code, ExitUsage)
			}
			var env envelope
			isJSON := json.Unmarshal(stderr.Bytes(), &env) == nil
			gotUsage := strings.Contains(stderr.String(), "Exit codes") || (isJSON && env.Error.Usage == tlsUsage)
			if gotUsage != tt.wantUsage {
				t.Errorf("whole help in stderr = %v, want %v:\n%s", gotUsage, tt.wantUsage, stderr.String())
			}
			if strings.Contains(stderr.String(), intro) && tt.env != nil {
				t.Errorf("stderr = %q, want no intro for an agent", stderr.String())
			}
		})
	}
}
