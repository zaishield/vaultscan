// deprecation.go — emits RFC 8594 Sunset + RFC draft Deprecation
// headers for routes the platform has marked obsolete.
//
// API versioning policy:
//
//   - We announce deprecation by mounting the legacy route via
//     Deprecated(...) which adds the headers:
//
//	Deprecation: true
//	Sunset:      <RFC1123 UTC date>
//	Link:        <https://docs/...>; rel="successor-version"
//
//   - Clients hitting a deprecated route get a working response (so
//     nothing breaks) AND a header set their HTTP client libraries can
//     surface ahead of time. The Sunset date is at least 90 days in
//     the future at the time of marking — this gives integrators a
//     full quarter to migrate.
//
//   - After Sunset the route is rewritten to 410 Gone (NOT removed
//     silently); the 410 body carries the same Link header so the
//     migrating client gets the same successor pointer.
//
// Why a middleware instead of inline writes: keeps the policy in one
// place (search "Deprecated(" to enumerate every deprecated route),
// and the test harness can fail-build when a Sunset date in the past
// is still mounted via Deprecated rather than Gone.
package middleware

import (
	"net/http"
	"time"
)

// Deprecated wraps a handler with Deprecation/Sunset/Link headers.
//
// successor is the URL of the replacement route (absolute or relative);
// pass "" to omit the Link header (rare — only for endpoints being
// retired with no successor).
//
// sunset is the date after which the endpoint becomes 410. Past dates
// are still emitted as-is so monitoring catches "Sunset already
// happened but route still live" via header inspection.
func Deprecated(sunset time.Time, successor string) func(http.Handler) http.Handler {
	sunsetHeader := sunset.UTC().Format(http.TimeFormat)
	link := ""
	if successor != "" {
		link = "<" + successor + ">; rel=\"successor-version\""
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Deprecation", "true")
			w.Header().Set("Sunset", sunsetHeader)
			if link != "" {
				w.Header().Add("Link", link)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Gone returns a 410 handler for endpoints that have passed their
// Sunset date. Body is a small JSON envelope so portal/SDK callers
// get a structured "go away, here's where to go" response.
//
// The Link header mirrors the prior Deprecated() value so a client
// that ignored the deprecation warning still gets routed to the
// successor.
func Gone(successor string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if successor != "" {
			w.Header().Set("Link", "<"+successor+">; rel=\"successor-version\"")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":{"code":"endpoint_retired","successor":"` + successor + `","message":"this endpoint has been retired; see Link header"}}`))
	}
}
