package cli

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// loadRoots returns the system roots plus every certificate in the PEM
// files, so a scan trusts an internal CA and still trusts public ones. With
// no files it returns nil, which means the system roots alone.
func loadRoots(files []string) (*x509.CertPool, *Error) {
	if len(files) == 0 {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, name := range files {
		data, err := os.ReadFile(name) //nolint:gosec // G304: reading the file the user named is the purpose of --ca-file.
		if err != nil {
			return nil, failf(CodeInvalidCAFile, "%v", err)
		}
		added := 0
		for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, failf(CodeInvalidCAFile, "%s: %v", name, err)
			}
			pool.AddCert(cert)
			added++
		}
		if added == 0 {
			return nil, failf(CodeInvalidCAFile, "%s holds no PEM certificate", name)
		}
	}
	return pool, nil
}
