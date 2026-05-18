// middleware_scim.go — bearer-token auth for the /scim/v2 endpoints.
//
// Wires scimtokens.Service.Verify to authenticate IdP SCIM
// connectors. The IdP sends:
//   Authorization: Bearer vss_<token>
//   X-Tenant-Id:   <uuid>
//
// Middleware looks up the (tenant_id, token) pair, sets the tenant
// in the request context, and lets the SCIMServer handler run.

package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/scimtokens"
)

// SCIMTenantCtxKey is the context key the SCIM server reads to
// scope its queries.
type SCIMTenantCtxKey struct{}

// SCIMTokenAuth returns chi middleware that validates the bearer
// token against tenant_scim_tokens via scimtokens.Verify.
//
// Failure modes (always 401, never 500 — the IdP gets a clear
// signal it should rotate its secret):
//   - no Authorization header
//   - no X-Tenant-Id header
//   - non-UUID X-Tenant-Id
//   - token not matched OR matched-but-revoked OR matched-but-expired
//
// On success the request context carries the tenant_id under
// SCIMTenantCtxKey, and `vaultscan.tenant_id` GUC is set so the
// downstream SCIMServer's queries naturally get RLS.
func SCIMTokenAuth(svc *scimtokens.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_request"`)
				http.Error(w, `{"error":"missing_bearer"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")

			tenantStr := r.Header.Get("X-Tenant-Id")
			if tenantStr == "" {
				http.Error(w, `{"error":"missing_tenant"}`, http.StatusUnauthorized)
				return
			}
			tenantID, err := uuid.Parse(tenantStr)
			if err != nil {
				http.Error(w, `{"error":"invalid_tenant"}`, http.StatusUnauthorized)
				return
			}

			tok, err := svc.Verify(r.Context(), tenantID, token, clientIPv4(r))
			if err != nil {
				http.Error(w, `{"error":"verify_failed"}`, http.StatusUnauthorized)
				return
			}
			if tok == nil {
				w.Header().Set("WWW-Authenticate",
					`Bearer realm="scim", error="invalid_token"`)
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), SCIMTenantCtxKey{}, tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// clientIPv4 extracts the request's source IP for the audit
// trail. Same helper logic as the rest of the middleware (trusts
// X-Forwarded-For only when a trusted-proxy chain is configured;
// here we just take the first non-loopback hop).
func clientIPv4(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, raw := range strings.Split(xff, ",") {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip != nil && !ip.IsLoopback() {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// TenantFromSCIMContext returns the tenant ID set by SCIMTokenAuth.
// SCIMServer handlers use this to scope their queries.
func TenantFromSCIMContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(SCIMTenantCtxKey{}).(uuid.UUID)
	return v, ok
}
