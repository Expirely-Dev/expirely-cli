package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/expirely-dev/expirely-cli/internal/tls/target"
	"github.com/expirely-dev/expirely-cli/internal/tls/tlstest"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCollectTargets(t *testing.T) {
	file := writeFile(t, "# production\n\nb.example\n  c.example:8443  \nhttps://a.example/\n")

	got, e := collectTargets([]string{"a.example", "b.example"}, []string{file, "-"}, strings.NewReader("d.example\n# done\n"))
	if e != nil {
		t.Fatalf("collectTargets() error = %v", e)
	}

	want := []target.Target{
		{Host: "a.example", Port: 443},
		{Host: "b.example", Port: 443},
		{Host: "c.example", Port: 8443},
		{Host: "d.example", Port: 443},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("collectTargets() = %v, want %v (arguments first, files in order, repeats dropped)", got, want)
	}
}

func TestCollectTargetsErrors(t *testing.T) {
	bad := writeFile(t, "ok.example\n\nhttp://plain.example\n")
	missing := filepath.Join(t.TempDir(), "missing.txt")

	tests := []struct {
		name     string
		files    []string
		stdin    string
		wantCode string
		wantMsg  string
	}{
		{name: "invalid line names file and line", files: []string{bad}, wantCode: CodeInvalidTarget, wantMsg: bad + `:3: invalid target "http://plain.example"`},
		{name: "invalid stdin line", files: []string{"-"}, stdin: "x.example:0\n", wantCode: CodeInvalidTarget, wantMsg: "stdin:1: invalid target"},
		{name: "missing file", files: []string{missing}, wantCode: CodeFileUnreadable, wantMsg: "missing.txt"},
		{name: "line too long", files: []string{"-"}, stdin: strings.Repeat("a", 70*1024), wantCode: CodeFileUnreadable, wantMsg: "read stdin: bufio.Scanner: token too long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, e := collectTargets(nil, tt.files, strings.NewReader(tt.stdin))
			if e == nil {
				t.Fatal("collectTargets() error = nil, want an error")
			}
			if e.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", e.Code, tt.wantCode)
			}
			if !strings.Contains(e.Message, tt.wantMsg) {
				t.Errorf("message = %q, want it to contain %q", e.Message, tt.wantMsg)
			}
		})
	}
}

func TestRunReadsTargetsFromStdin(t *testing.T) {
	ca := tlstest.NewCA(t)
	port := tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*24*time.Hour)))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"tls", "-f", "-", "--concurrency", "2"}, Streams{
		Stdin:  strings.NewReader(fmt.Sprintf("# from a pipe\nlocalhost:%d\nlocalhost:%d\n", port, port)),
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d; stderr = %s", code, ExitOK, stderr.String())
	}
	var got scanReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\n%s", err, stdout.String())
	}
	if len(got.Results) != 1 || got.Results[0].Target != fmt.Sprintf("localhost:%d", port) {
		t.Errorf("results = %+v, want one result for the repeated target", got.Results)
	}
}

func TestRunFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "concurrency below one", args: []string{"--concurrency", "0", "a.example"}, wantErr: "--concurrency must be 1 or more, got 0"},
		{name: "empty file and no arguments", args: []string{"-f", "-"}, wantErr: "expirely: no targets in stdin\nTargets come as arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(t, true, tt.args...)
			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d", code, ExitUsage)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
		})
	}
}
