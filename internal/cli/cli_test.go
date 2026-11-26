package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func run(t *testing.T, terminal bool, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, Streams{
		Stdin:            strings.NewReader(""),
		Stdout:           &out,
		Stderr:           &errOut,
		StdoutIsTerminal: terminal,
	})
	return code, out.String(), errOut.String()
}

func TestRunText(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no arguments prints usage to stderr",
			wantCode:   ExitUsage,
			wantStderr: "expirely: nothing to do: pass a flag\n\nUsage: expirely",
		},
		{
			name:       "help prints usage to stdout",
			args:       []string{"--help"},
			wantCode:   ExitOK,
			wantStdout: "Usage: expirely",
		},
		{
			name:       "version prints the build version",
			args:       []string{"--version"},
			wantCode:   ExitOK,
			wantStdout: "expirely ",
		},
		{
			name:       "unknown flag is a usage error",
			args:       []string{"--nope"},
			wantCode:   ExitUsage,
			wantStderr: "expirely: flag provided but not defined: -nope\n\nUsage: expirely",
		},
		{
			name:       "positional argument is a usage error",
			args:       []string{"example.com"},
			wantCode:   ExitUsage,
			wantStderr: `expirely: unexpected argument "example.com"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, true, tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.HasPrefix(stdout, tt.wantStdout) || (tt.wantStdout == "" && stdout != "") {
				t.Errorf("stdout = %q, want prefix %q", stdout, tt.wantStdout)
			}
			if !strings.HasPrefix(stderr, tt.wantStderr) || (tt.wantStderr == "" && stderr != "") {
				t.Errorf("stderr = %q, want prefix %q", stderr, tt.wantStderr)
			}
		})
	}
}

func TestRunJSONErrors(t *testing.T) {
	tests := []struct {
		name     string
		terminal bool
		args     []string
		wantCode int
		wantErr  string
	}{
		{name: "stdout not a terminal", terminal: false, args: []string{"--nope"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
		{name: "json flag after a bad flag", terminal: true, args: []string{"--nope", "--json"}, wantCode: ExitUsage, wantErr: CodeInvalidFlag},
		{name: "unexpected argument", terminal: true, args: []string{"--json", "example.com"}, wantCode: ExitUsage, wantErr: CodeUnexpectedArgument},
		{name: "no arguments", terminal: false, wantCode: ExitUsage, wantErr: CodeMissingArguments},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.terminal, tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			var got struct {
				Error struct {
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stderr), &got); err != nil {
				t.Fatalf("stderr is not the JSON error envelope: %v\n%s", err, stderr)
			}
			if got.Error.Code != tt.wantErr {
				t.Errorf("error code = %q, want %q", got.Error.Code, tt.wantErr)
			}
			if got.Error.Message == "" {
				t.Error("error message is empty")
			}
		})
	}
}

func TestRunJSONVersion(t *testing.T) {
	code, stdout, stderr := run(t, false, "--version")

	if code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if got["version"] == "" {
		t.Errorf("version = %q, want non-empty", got["version"])
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: failingWriter{},
		Stderr: &stderr,
	})

	if code != ExitFailure {
		t.Errorf("exit code = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), `"code":"output_failed"`) {
		t.Errorf("stderr = %q, want the output_failed code", stderr.String())
	}
}

func TestFailfRejectsUnknownCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("failf with an unknown code did not panic")
		}
	}()
	_ = failf("no_such_code", "x")
}

func TestReadmeListsEveryCode(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	for code, exit := range errorCodes {
		row := "| `" + code + "` |"
		if !bytes.Contains(readme, []byte(row)) {
			t.Errorf("README has no row %q for exit code %d", row, exit)
		}
	}
}
