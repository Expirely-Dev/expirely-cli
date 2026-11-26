package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no arguments prints usage to stderr",
			args:       nil,
			wantCode:   ExitUsage,
			wantStderr: "Usage: expirely",
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
			wantStderr: "flag provided but not defined: -nope",
		},
		{
			name:       "positional argument is a usage error",
			args:       []string{"example.com"},
			wantCode:   ExitUsage,
			wantStderr: `unexpected argument "example.com"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run(context.Background(), tt.args, Streams{
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			})

			if got != tt.wantCode {
				t.Errorf("exit code = %d, want %d", got, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStdout == "" && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}
