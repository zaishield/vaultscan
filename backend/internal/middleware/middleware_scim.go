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

	authpkg "github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/db"
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

			// Synthesise a service-account Identity scoped to the
			// tenant the token belongs to. Without this, downstream
			// SCIM handlers calling auth.FromContext() get a nil
			// Identity and either nil-deref-panic or 403 with no
			// useful signal. Permissions are deliberately the
			// minimum SCIM needs (`manage_users`); SCIM does not
			// get the full tenant_admin set even though the token
			// was minted by a tenant admin.
			//
			// Roles list is empty so super_admin short-circuit in
			// Identity.Has does NOT fire — every permission check
			// goes through the explicit Permissions map.
			identity := &authpkg.Identity{
				UserID:      tok.ID,
				Email:       "scim-token:" + tok.Label,
				PlatformID:  uuid.Nil, // resolved by handlers via tenant lookup
				PartnerID:   nil,
				TenantID:    &tenantID,
				Roles:       []string{"scim_provisioner"},
				Permissions: map[string]bool{"manage_users": true},
				MFAVerified: true, // SCIM doesn't surface MFA — the token IS the credential
			}
			ctx := context.WithValue(r.Context(), SCIMTenantCtxKey{}, tenantID)
			ctx = authpkg.ContextWithIdentity(ctx, identity)
			// Bind the tenant into the DB context too so the pool's
			// BeforeAcquire hook engages RLS on every conn the
			// downstream SCIMServer borrows. Without this, the
			// SCIMServer's `WHERE tenant_id = $1` was the sole
			// isolation; an accidental missing predicate on a future
			// SCIM query would leak cross-tenant.
			ctx = db.ContextWithTenantBinding(ctx, tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// clientIPv4 extracts the request's source IP for the audit trail.
// Delegates to the shared ClientIP helper which honours the
// TrustedProxyCIDRs allowlist — without that, an attacker can spoof
// X-Forwarded-For directly and forge last_used_ip on SCIM tokens.
func clientIPv4(r *http.Request) net.IP {
	return ClientIP(r)
}

// TenantFromSCIMContext returns the tenant ID set by SCIMTokenAuth.
// SCIMServer handlers use this to scope their queries.
func TenantFromSCIMContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(SCIMTenantCtxKey{}).(uuid.UUID)
	return v, ok
}
