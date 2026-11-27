// Package gcptest serves fake Compute Engine API responses for tests, so
// code that lists SSL certificates and proxies runs without Google Cloud.
package gcptest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fake holds the JSON bodies the fake Compute API returns, keyed by the
// path after the project, such as "aggregated/sslCertificates". A path
// with no body answers 404. Status, when set, answers every request with
// that status code and a Google API error body instead, with Reason as its
// ErrorInfo reason when Reason is set.
type Fake struct {
	Bodies map[string]any
	Status int
	Reason string
}

// Serve starts the fake API for project and returns the endpoint to pass
// as gcp.Service.Endpoint. The server stops when the test ends.
func Serve(t testing.TB, project string, f Fake) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.Status != 0 {
			details := []any{}
			if f.Reason != "" {
				details = append(details, map[string]any{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": f.Reason, "domain": "googleapis.com"})
			}
			w.WriteHeader(f.Status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": f.Status, "message": "refused by the fake", "details": details}})
			return
		}
		prefix := "/compute/v1/projects/" + project + "/"
		body, ok := f.Bodies[strings.TrimPrefix(r.URL.Path, prefix)]
		if !strings.HasPrefix(r.URL.Path, prefix) || !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/compute/v1/"
}

// Sample returns bodies for a project with a self-managed global
// certificate used by two proxies, a managed one used by none, and a
// self-managed regional one used by a regional proxy.
func Sample(project string) map[string]any {
	link := func(scope, kind, name string) string {
		return "https://compute.googleapis.com/compute/v1/projects/" + project + "/" + scope + "/" + kind + "/" + name
	}
	return map[string]any{
		"aggregated/sslCertificates": map[string]any{
			"items": map[string]any{
				"global": map[string]any{"sslCertificates": []any{
					map[string]any{"name": "api-cert", "type": "SELF_MANAGED", "selfLink": link("global", "sslCertificates", "api-cert"), "subjectAlternativeNames": []string{"api.example.com"}, "expireTime": "2026-12-08T12:00:00.000-08:00"},
					map[string]any{"name": "www-managed", "type": "MANAGED", "selfLink": link("global", "sslCertificates", "www-managed"), "managed": map[string]any{"domains": []string{"www.example.com"}, "status": "ACTIVE"}, "expireTime": "2027-01-26T00:00:00Z"},
					map[string]any{"name": "pending", "type": "MANAGED", "selfLink": link("global", "sslCertificates", "pending"), "managed": map[string]any{"domains": []string{"new.example.com"}, "status": "PROVISIONING"}},
				}},
				"regions/us-central1": map[string]any{"sslCertificates": []any{
					map[string]any{"name": "internal", "type": "SELF_MANAGED", "selfLink": link("regions/us-central1", "sslCertificates", "internal"), "subjectAlternativeNames": []string{"internal.example.com"}, "expireTime": "2027-06-17T00:00:00Z"},
				}},
				"regions/europe-west1": map[string]any{"warning": map[string]any{"code": "NO_RESULTS_ON_PAGE"}},
			},
		},
		"aggregated/targetHttpsProxies": map[string]any{
			"items": map[string]any{
				"global": map[string]any{"targetHttpsProxies": []any{
					map[string]any{"name": "api-https", "selfLink": link("global", "targetHttpsProxies", "api-https"), "sslCertificates": []string{link("global", "sslCertificates", "api-cert")}},
				}},
				"regions/us-central1": map[string]any{"targetHttpsProxies": []any{
					map[string]any{"name": "internal-https", "selfLink": link("regions/us-central1", "targetHttpsProxies", "internal-https"), "sslCertificates": []string{link("regions/us-central1", "sslCertificates", "internal")}},
				}},
			},
		},
		"global/targetSslProxies": map[string]any{
			"items": []any{
				map[string]any{"name": "api-ssl", "selfLink": link("global", "targetSslProxies", "api-ssl"), "sslCertificates": []string{link("global", "sslCertificates", "api-cert")}},
			},
		},
	}
}
