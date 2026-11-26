package cli

import "strings"

// agent is what expirely knows about an AI agent running it. Name is empty
// when no agent was detected. Any detected agent gets no spinner and no
// color; a declared one also gets JSON on a terminal, since it asked for
// machine output by saying what it is.
type agent struct {
	Name     string
	Declared bool
}

// vendorMarkers are environment variables coding agents set in the
// commands they run. A Codex marker counts as declared because Codex gives
// every command a pseudo-terminal, so a terminal there does not mean a
// person is reading.
var vendorMarkers = []struct {
	env      string
	name     string
	declared bool
}{
	{"CODEX_SANDBOX", "codex", true},
	{"CODEX_CI", "codex", true},
	{"CODEX_THREAD_ID", "codex", true},
	{"GEMINI_CLI", "gemini-cli", false},
	{"CURSOR_AGENT", "cursor", false},
	{"COPILOT_CLI", "copilot", false},
	{"OPENCODE", "opencode", false},
	{"CLAUDE_CODE_CHILD_SESSION", "claude-code", false},
}

// detectAgent reads getenv in this order and stops at the first match:
//
//  1. EXPIRELY_AGENT: 1 or true declares an agent, 0 or false declares a
//     person and turns detection off;
//  2. AI_AGENT, then AGENT: the agent's name, declared;
//  3. vendor markers, such as CODEX_SANDBOX or GEMINI_CLI;
//  4. CLAUDECODE=1, only when stdout is not a terminal, because IDE
//     terminals that people type in set it too.
//
// A nil getenv detects nothing.
func detectAgent(getenv func(string) string, stdoutIsTerminal bool) agent {
	if getenv == nil {
		return agent{}
	}
	switch strings.ToLower(getenv("EXPIRELY_AGENT")) {
	case "1", "true":
		return agent{Name: "expirely-agent", Declared: true}
	case "0", "false":
		return agent{}
	}
	for _, env := range []string{"AI_AGENT", "AGENT"} {
		if v := getenv(env); v != "" && v != "0" && !strings.EqualFold(v, "false") {
			return agent{Name: v, Declared: true}
		}
	}
	for _, m := range vendorMarkers {
		if getenv(m.env) != "" {
			return agent{Name: m.name, Declared: m.declared}
		}
	}
	if getenv("CLAUDECODE") == "1" && !stdoutIsTerminal {
		return agent{Name: "claude-code"}
	}
	return agent{}
}
