// Package gcptest serves fake Compute Engine and Certificate Manager API
// responses for tests, so code that lists certificates runs without Google
// Cloud.
package gcptest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fake holds the responses of the fake APIs, keyed by the path after the
// project, such as "aggregated/sslCertificates" for Compute or
// "locations/global/certificates" for Certificate Manager. A value is
// encoded as the JSON body, except an Error, which answers with its status,
// and nil, which answers an empty object. A path with no key answers 404.
// Status, when set, answers every request as Error{Status, Reason} would.
type Fake struct {
	Bodies map[string]any
	Status int
	Reason string
}

// Error is a Google API error response: Status, with Reason as its
// ErrorInfo reason when Reason is set.
type Error struct {
	Status int
	Reason string
}

// Endpoints are the base URLs of the fake APIs, for gcp.Service.
type Endpoints struct {
	Compute            string
	CertificateManager string
}

// Serve starts the fake APIs for project. The server stops when the test
// ends.
func Serve(t testing.TB, project string, f Fake) Endpoints {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.Status != 0 {
			writeError(w, Error{Status: f.Status, Reason: f.Reason})
			return
		}
		var body any
		found := false
		for _, prefix := range []string{"/compute/v1/projects/" + project + "/", "/certificatemanager/v1/projects/" + project + "/"} {
			if rest, ok := strings.CutPrefix(r.URL.Path, prefix); ok {
				body, found = f.Bodies[rest]
			}
		}
		switch b := body.(type) {
		case Error:
			writeError(w, b)
		case nil:
			if !found {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("{}"))
		default:
			_ = json.NewEncoder(w).Encode(b)
		}
	}))
	t.Cleanup(srv.Close)
	return Endpoints{Compute: srv.URL + "/compute/v1/", CertificateManager: srv.URL + "/certificatemanager/v1/"}
}

func writeError(w http.ResponseWriter, e Error) {
	details := []any{}
	if e.Reason != "" {
		details = append(details, map[string]any{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": e.Reason, "domain": "googleapis.com"})
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": e.Status, "message": "refused by the fake", "details": details}})
}

// Sample returns responses for a project with, in Compute, a self-managed
// global certificate used by two proxies, a managed one used by none, one
// still provisioning and a self-managed regional one used by a regional
// proxy; and in Certificate Manager, a managed global certificate used by a
// map entry, a self-managed regional one nothing uses and a location with
// none.
func Sample(project string) map[string]any {
	link := func(scope, kind, name string) string {
		return "https://compute.googleapis.com/compute/v1/projects/" + project + "/" + scope + "/" + kind + "/" + name
	}
	location := func(id string) map[string]any {
		return map[string]any{"locationId": id, "name": "projects/" + project + "/locations/" + id}
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
		"locations": map[string]any{
			"locations": []any{location("global"), location("us-east1"), location("europe-west4")},
		},
		"locations/global/certificates": map[string]any{
			"certificates": []any{map[string]any{
				"name":        "projects/" + project + "/locations/global/certificates/shop-cm",
				"sanDnsnames": []string{"shop.example.com"},
				"expireTime":  "2027-02-01T00:00:00Z",
				"managed":     map[string]any{"domains": []string{"shop.example.com"}, "state": "ACTIVE"},
				"usedBy":      []any{map[string]any{"name": "//certificatemanager.googleapis.com/projects/" + project + "/locations/global/certificateMaps/main/certificateMapEntries/shop"}},
			}},
		},
		"locations/us-east1/certificates": map[string]any{
			"certificates": []any{map[string]any{
				"name":        "projects/" + project + "/locations/us-east1/certificates/legacy-cm",
				"sanDnsnames": []string{"legacy.example.com"},
				"expireTime":  "2026-12-01T00:00:00Z",
				"selfManaged": map[string]any{},
			}},
		},
		"locations/europe-west4/certificates": nil,
	}
}
