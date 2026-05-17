// Package middleware composes authentication, tenant context, audit, and rate
// limiting layers in front of every API handler.
package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/db"
)

// authLogger emits the rejected-token detail server-side so operators
// keep diagnosis power without the client learning anything beyond
// "unauthorized". Echoing err.Error() back leaks whether the kid was
// unknown, the signature failed, the alg was banned, the token was
// expired, etc. — exactly the breadcrumbs an attacker tunes against.
var authLogger = zerolog.New(os.Stderr).With().
	Timestamp().Str("component", "auth-mw").Logger()

// AuthFunc is the JWT verifier injected by the API server.
type AuthFunc func(r *http.Request) (*auth.Identity, error)

// Auth requires every request carry a valid bearer token.
func Auth(verify AuthFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := verify(r)
			if err != nil {
				authLogger.Warn().
					Err(err).
					Str("remote_addr", r.RemoteAddr).
					Str("path", r.URL.Path).
					Msg("auth: token rejected")
				writeJSONError(w, http.StatusUnauthorized, "unauthorized",
					"invalid or missing bearer token")
				return
			}
			r = r.WithContext(auth.ContextWithIdentity(r.Context(), id))
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission enforces a permission check after Auth.
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := auth.FromContext(r.Context())
			if err != nil || !id.Has(perm) {
				writeJSONError(w, http.StatusForbidden, "forbidden",
					"permission required: "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireMFA enforces that the bearer's identity has an MFA-verified token.
func RequireMFA() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := auth.FromContext(r.Context())
			if err != nil || !id.MFAVerified {
				writeJSONError(w, http.StatusForbidden, "mfa_required",
					"action requires MFA-verified session")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TenantScope ensures the request's tenant_id matches the identity's tenant
// (Blueprint §9.3).
//
// Behaviour:
//   - ZAISHIELD super admin → pass through (operator path; may
//     legitimately query across tenants).
//   - Header supplied:        verify it matches identity.TenantID.
//     On mismatch the request is refused with 403.
//   - Header NOT supplied:    if the identity has a TenantID, the
//     header is auto-populated from identity (the previous version
//     of this middleware silently fell through here, which left
//     downstream filtering as the sole defence — a service-layer
//     bug could leak cross-tenant data). If the identity has no
//     TenantID (platform / partner role), the request passes
//     through with no header — those callers run unbound and must
//     filter explicitly.
func TenantScope(headerName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := auth.FromContext(r.Context())
			if id != nil && id.HasRole("zaishield_super_admin") {
				next.ServeHTTP(w, r)
				return
			}
			requested := r.Header.Get(headerName)
			if requested == "" {
				// Auto-bind to the identity's tenant if one exists,
				// so RLS / WHERE filtering always sees a concrete
				// tenant_id. Platform/partner roles (no TenantID)
				// still pass through unbound — those paths are
				// expected to filter by partner_id / platform_id.
				if id != nil && id.TenantID != nil {
					r.Header.Set(headerName, id.TenantID.String())
				}
				next.ServeHTTP(w, r)
				return
			}
			tid, err := uuid.Parse(requested)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "bad_tenant",
					"invalid tenant header")
				return
			}
			if id == nil || id.TenantID == nil || *id.TenantID != tid {
				writeJSONError(w, http.StatusForbidden, "tenant_mismatch",
					"identity is not bound to the requested tenant")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TenantBinding pre-sets the vaultscan.tenant_id GUC on the pool so the
// RLS policies on every tenant-scoped table engage for the lifetime of
// this request. The set_config(_, _, false) form sets at session scope;
// pool connection reuse means a second request could inherit the GUC
// briefly before this middleware overwrites it, so this is defense-in-
// depth on top of the application's WHERE-clause filtering, not a sole
// safety net.
//
// Behaviour:
//   - identity has TenantID: SET vaultscan.tenant_id = '<uuid>' → RLS
//     binds to that tenant.
//   - identity has no TenantID (platform / partner role): leave GUC
//     untouched (NULL → pass-through). If the previous request set a
//     tenant, clear it explicitly to avoid leak between unrelated
//     callers.
//
// Errors are logged-and-ignored: the WHERE-clause discipline still
// applies, so a failed SET doesn't open a leak.
func TenantBinding(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := auth.FromContext(r.Context())
			if id != nil && id.TenantID != nil {
				_ = db.SetTenantContext(r.Context(), pool, *id.TenantID)
			} else {
				_ = db.ClearTenantContext(r.Context(), pool)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDKey is the ctx key under which the request ID lives.
// Handlers and services pull it via RequestIDFromContext for log
// correlation. Operators tracing a slow request across the API +
// scanner-worker logs all key off this same UUID.
type requestIDCtxKey struct{}

// RequestIDFromContext returns the request ID stamped by the
// RequestID middleware, or "" if none.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// RequestID stamps every request with a correlation ID surfaced in
// responses, the request ctx (for downstream log correlation), and
// audit log entries.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := r.Header.Get("X-Request-Id")
			if rid == "" {
				rid = uuid.New().String()
			}
			w.Header().Set("X-Request-Id", rid)
			r = r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, rid))
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodySize caps the request body bytes a handler can read. Wraps
// r.Body in http.MaxBytesReader so any io.ReadAll / json.Decoder
// that crosses the limit returns an error rather than allocating
// unbounded memory. 32 MiB is the default — comfortably above the
// largest legitimate request (multipart asset upload at 5 MiB,
// authdocs at 10 MiB) and small enough to stop a single OOM attempt.
func MaxBodySize(limitBytes int64) func(http.Handler) http.Handler {
	if limitBytes <= 0 {
		limitBytes = 32 << 20
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// APIVersion stamps an X-API-Version header on every response so
// clients can detect rolling-deploy version skew (their cached
// schema may be stale). The header carries the build-time version
// string from cmd/api — set via -ldflags at release time, defaults
// to "dev".
func APIVersion(version string) func(http.Handler) http.Handler {
	if version == "" {
		version = "dev"
	}
	// Strip CR / LF before stamping the value into a response header.
	// Build-time -ldflags substitution is the only writer today, so
	// untrusted input is unlikely — this is defence-in-depth against
	// a future refactor that wires a config var here. Without
	// sanitisation a malformed value containing "\r\nSet-Cookie: ..."
	// would inject a header.
	version = strings.ReplaceAll(version, "\r", "")
	version = strings.ReplaceAll(version, "\n", "")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-API-Version", version)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets a conservative baseline of HTTP security headers
// (HS-01).
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// HSTS — 2 years + subdomains. preload is left to the
			// edge LB which is responsible for the apex domain.
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy",
				"geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()")
			h.Set("Content-Security-Policy",
				"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
			// Cross-origin isolation. The portal mounts our API in
			// a same-origin iframe-free context; setting these
			// hardens against spectre-class side channels and
			// cross-window leaks.
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cross-Origin-Embedder-Policy", "require-corp")
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit is a simple token-bucket per identity / IP.
type RateLimit struct {
	rps     int
	burst   int
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewRateLimit(rps int) *RateLimit {
	if rps <= 0 {
		rps = 100
	}
	return &RateLimit{rps: rps, burst: rps * 2, buckets: map[string]*bucket{}}
}

func (rl *RateLimit) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := identityKey(r)
			if !rl.allow(key) {
				writeJSONError(w, http.StatusTooManyRequests, "rate_limited",
					"slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func identityKey(r *http.Request) string {
	if id, err := auth.FromContext(r.Context()); err == nil {
		return "user:" + id.UserID.String()
	}
	// Use the trust-gated source IP — without this an attacker could
	// spoof X-Forwarded-For to pivot through rate-limiter buckets and
	// evade the per-IP throttle entirely.
	if ip := ClientIP(r); ip != nil {
		return "ip:" + ip.String()
	}
	return "ip:" + strings.Split(r.RemoteAddr, ":")[0]
}

func (rl *RateLimit) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), lastRefill: now}
		rl.buckets[key] = b
	}
	delta := now.Sub(b.lastRefill).Seconds()
	b.tokens = minF(float64(rl.burst), b.tokens+delta*float64(rl.rps))
	b.lastRefill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
