// Package debugserver mounts the Go runtime's pprof handlers on a
// dedicated port that is NEVER exposed to public traffic. Production
// deployments bind this to localhost (or the cluster-internal pod IP)
// and put it behind an admin-only network policy + bearer token.
//
// Why not co-host on the API server: pprof is a CPU/memory profiling
// goldmine for an attacker who reaches it. Mixing it with the public
// API means a single network-policy mistake exposes /debug/pprof.
// A dedicated server with its own auth makes the boundary explicit.
//
// Bearer token: VAULTSCAN_PPROF_TOKEN. Empty in dev (anyone on the
// loopback can scrape). Production guard requires it to be set when
// VAULTSCAN_ENV=production.
package debugserver

import (
	"crypto/subtle"
	"net/http"
	"net/http/pprof"
	"time"
)

// New returns an *http.Server already wired with pprof handlers.
// Caller is responsible for ListenAndServe + Shutdown.
//
//	tokenSecret: bearer token required on every /debug/pprof/* hit.
//	            Empty string = no auth (DEV ONLY). Production guard
//	            enforces non-empty when VAULTSCAN_ENV=production.
func New(addr, tokenSecret string) *http.Server {
	mux := http.NewServeMux()
	// pprof standard handlers under /debug/pprof — same paths the
	// go tool pprof CLI fetches by default.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	// Lightweight liveness probe so the operator's curl can confirm
	// the debug server is up without authenticating.
	mux.HandleFunc("/debug/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := http.Handler(mux)
	if tokenSecret != "" {
		handler = bearerAuth(tokenSecret, mux)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		// pprof.Profile writes a continuous response for up to 30s;
		// don't trip WriteTimeout in the middle of a profile capture.
		WriteTimeout:   2 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 32 * 1024,
	}
}

// bearerAuth wraps next and demands "Authorization: Bearer <secret>"
// on every request. Uses constant-time comparison so a network-timing
// attacker can't probe the secret one byte at a time.
func bearerAuth(secret string, next http.Handler) http.Handler {
	want := []byte("Bearer " + secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness probe stays open; everything else needs the token.
		if r.URL.Path == "/debug/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vaultscan-debug"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
