package cli

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bycavii/expirely-cli/internal/tlstest"
)

func TestRunTrustsAnInternalCAFromCAFile(t *testing.T) {
	ca := tlstest.NewCA(t)
	target := fmt.Sprintf("localhost:%d", tlstest.ServeTLS(t, ca.Leaf(t, "localhost", time.Now().Add(90*24*time.Hour))))
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		args        []string
		wantTrusted bool
		wantIssue   any
	}{
		{name: "without the CA the issuer is unknown", args: []string{target}, wantTrusted: false, wantIssue: "unknown_authority"},
		{name: "with --ca-file the chain is trusted", args: []string{"--ca-file", caFile, target}, wantTrusted: true, wantIssue: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, false, tt.args...)
			if code != ExitOK {
				t.Fatalf("exit code = %d, want %d; stderr = %s", code, ExitOK, stderr)
			}
			var got struct {
				Results []struct {
					Trusted    bool `json:"trusted"`
					TrustIssue any  `json:"trust_issue"`
				}
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("stdout is not the JSON report: %v", err)
			}
			if r := got.Results[0]; r.Trusted != tt.wantTrusted || r.TrustIssue != tt.wantIssue {
				t.Errorf("trusted = %v, trust_issue = %v; want %v and %v", r.Trusted, r.TrustIssue, tt.wantTrusted, tt.wantIssue)
			}
		})
	}
}

func TestCAFileErrors(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "notes.txt")
	badCert := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		file    string
		wantMsg string
	}{
		{name: "missing file", file: filepath.Join(dir, "missing.pem"), wantMsg: "missing.pem"},
		{name: "no PEM certificate", file: notPEM, wantMsg: "holds no PEM certificate"},
		{name: "unparsable certificate", file: badCert, wantMsg: "bad.pem: x509:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(t, false, "--ca-file", tt.file, "example.com")

			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d", code, ExitUsage)
			}
			var env envelope
			if err := json.Unmarshal([]byte(stderr), &env); err != nil {
				t.Fatalf("stderr is not the error envelope: %v\n%s", err, stderr)
			}
			if env.Error.Code != CodeInvalidCAFile || !strings.Contains(env.Error.Message, tt.wantMsg) {
				t.Errorf("error = %+v, want code %q and a message containing %q", env.Error, CodeInvalidCAFile, tt.wantMsg)
			}
		})
	}
}
