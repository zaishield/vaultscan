// tenant_scope.go — multi-tenant authorization helpers.
//
// Background: every handler that accepts a tenant_id in its request body
// is a potential cross-tenant leak vector. The pattern below is the only
// safe one:
//
//   target, err := auth.AuthorizeTargetTenant(identity, req.TenantID)
//   if err != nil { writeJSONError(w, 403, "forbidden", err.Error()); return }
//
// Rules enforced (in priority order):
//
//   1. zaishield_super_admin / platform_admin → may target any tenant
//      (including nil to indicate "platform scope").
//
//   2. partner roles (partner_admin, partner_operator, distributor_admin,
//      reseller_admin) → may target any tenant if (a) we don't enforce
//      partner-tenant linkage here (the service layer joins on partner_id
//      and bounds rows) — they're constrained by their PartnerID at the
//      data-access layer, and (b) requested tenant is non-nil.
//
//   3. tenant_admin / tenant_operator / tenant_viewer → may target ONLY
//      their own TenantID. Any other tenant_id in the body is rejected
//      even if the database lookup would have succeeded.
//
//   4. No identity, no roles, or tenant_id empty when required → reject.
//
// The function is liberal in what it accepts (string or UUID, nil pointer
// or zero UUID) so handlers don't have to pre-parse.
package auth

import (
	"errors"
	"strings"

	"github.com/google/uuid"
)

// PlatformLevelRoles can target any tenant (or nil = platform scope).
var PlatformLevelRoles = map[string]bool{
	"zaishield_super_admin": true,
	"platform_admin":        true,
	"platform_operator":     true,
}

// PartnerLevelRoles are scoped to their PartnerID by the service layer;
// tenant_id in the body is treated as a hint, but they're still allowed
// to specify any tenant under their partner.
var PartnerLevelRoles = map[string]bool{
	"distributor_admin": true,
	"reseller_admin":    true,
	"mssp_admin":        true,
	"partner_admin":     true,
	"partner_operator":  true,
}

// TenantLevelRoles are bound to a single tenant and CANNOT cross-tenant.
var TenantLevelRoles = map[string]bool{
	"tenant_admin":    true,
	"tenant_operator": true,
	"tenant_analyst":  true,
	"tenant_viewer":   true,
	"client_viewer":   true,
}

// ErrCrossTenantForbidden indicates the caller tried to target a tenant
// outside their authorization scope.
var ErrCrossTenantForbidden = errors.New("cross-tenant operation forbidden")

// ErrTenantRequired indicates the caller did not specify a tenant and
// the handler needs one. Tenant-level callers fall back to their own
// TenantID automatically; this fires for platform/partner callers who
// must be explicit.
var ErrTenantRequired = errors.New("tenant_id required")

// PartnerTenantChecker resolves whether the requested tenant belongs
// to the partner. Returns true if the partner-tenant linkage exists.
// Pass via WithPartnerTenantCheck to make AuthorizeTargetTenant
// enforce the linkage for partner-level identities.
type PartnerTenantChecker func(partnerID, tenantID uuid.UUID) bool

// AuthorizeOption tunes AuthorizeTargetTenant behaviour.
type AuthorizeOption func(*authorizeOpts)

type authorizeOpts struct {
	checkPartnerLinkage PartnerTenantChecker
}

// WithPartnerTenantCheck registers a closure that AuthorizeTargetTenant
// will call for partner-level identities. The closure must return true
// only when the requested tenant is in the caller's partner. Callers
// should pass a DB-backed implementation here (see DefaultPartnerTenantChecker).
//
// Without this option, partner-level identities can target any tenant —
// previously the only safety net was the service layer's JOIN on
// partner_id, which is easy to forget on a new handler. Setting the
// check makes the gate explicit at the authorization boundary.
func WithPartnerTenantCheck(fn PartnerTenantChecker) AuthorizeOption {
	return func(o *authorizeOpts) { o.checkPartnerLinkage = fn }
}

// AuthorizeTargetTenant verifies the identity is allowed to operate on
// requested. Returns the resolved tenant UUID (always non-nil on success).
//
// requested may be empty/zero — in which case:
//   - tenant-level callers: defaults to their TenantID
//   - partner/platform callers: error (must be explicit)
//
// Partner-level callers: when WithPartnerTenantCheck is provided, the
// requested tenant MUST belong to the caller's partner — otherwise
// ErrCrossTenantForbidden. Without that option, partner-tenant
// linkage is delegated to the service layer (legacy behaviour, kept
// for backward compat).
func AuthorizeTargetTenant(id *Identity, requested string, opts ...AuthorizeOption) (uuid.UUID, error) {
	if id == nil {
		return uuid.Nil, errors.New("no identity")
	}
	var o authorizeOpts
	for _, fn := range opts {
		fn(&o)
	}

	// Parse the requested tenant (lenient: empty is ok).
	requested = strings.TrimSpace(requested)
	var requestedID uuid.UUID
	if requested != "" {
		parsed, err := uuid.Parse(requested)
		if err != nil {
			return uuid.Nil, errors.New("tenant_id is not a valid UUID")
		}
		requestedID = parsed
	}

	// 1. Platform-level: anything goes.
	for _, role := range id.Roles {
		if PlatformLevelRoles[role] {
			if requestedID == uuid.Nil {
				return uuid.Nil, ErrTenantRequired
			}
			return requestedID, nil
		}
	}

	// 2. Partner-level: any tenant is allowed; the service layer's
	// JOIN on partner_id constrains the data scope. We still require
	// an explicit tenant. When a PartnerTenantChecker is wired, also
	// enforce the linkage here (defense-in-depth).
	for _, role := range id.Roles {
		if PartnerLevelRoles[role] {
			if requestedID == uuid.Nil {
				return uuid.Nil, ErrTenantRequired
			}
			if o.checkPartnerLinkage != nil && id.PartnerID != nil {
				if !o.checkPartnerLinkage(*id.PartnerID, requestedID) {
					return uuid.Nil, ErrCrossTenantForbidden
				}
			}
			return requestedID, nil
		}
	}

	// 3. Tenant-level: only their own.
	for _, role := range id.Roles {
		if TenantLevelRoles[role] {
			if id.TenantID == nil {
				return uuid.Nil, errors.New("tenant-level identity missing tenant_id claim")
			}
			if requestedID == uuid.Nil {
				return *id.TenantID, nil
			}
			if requestedID != *id.TenantID {
				return uuid.Nil, ErrCrossTenantForbidden
			}
			return *id.TenantID, nil
		}
	}

	// 4. No matching role.
	return uuid.Nil, errors.New("identity has no role authorizing tenant access")
}

// AuthorizeOptionalTenant is the same as AuthorizeTargetTenant but
// permits nil — for endpoints like createUser where TenantID is optional
// for platform-level callers (they might be creating a partner-level
// user). Returns a pointer so the caller can pass it through to a
// service layer that takes *uuid.UUID.
//
// Tenant-level callers MUST default to their own TenantID; the helper
// rejects them attempting to create platform-level users.
func AuthorizeOptionalTenant(id *Identity, requested string) (*uuid.UUID, error) {
	if id == nil {
		return nil, errors.New("no identity")
	}
	requested = strings.TrimSpace(requested)
	var requestedID *uuid.UUID
	if requested != "" {
		parsed, err := uuid.Parse(requested)
		if err != nil {
			return nil, errors.New("tenant_id is not a valid UUID")
		}
		requestedID = &parsed
	}

	for _, role := range id.Roles {
		if PlatformLevelRoles[role] {
			return requestedID, nil
		}
	}
	for _, role := range id.Roles {
		if PartnerLevelRoles[role] {
			// Partner roles can leave tenant nil (e.g. partner-level
			// integration) or set any tenant.
			return requestedID, nil
		}
	}
	for _, role := range id.Roles {
		if TenantLevelRoles[role] {
			if id.TenantID == nil {
				return nil, errors.New("tenant-level identity missing tenant_id claim")
			}
			if requestedID != nil && *requestedID != *id.TenantID {
				return nil, ErrCrossTenantForbidden
			}
			return id.TenantID, nil
		}
	}
	return nil, errors.New("identity has no role authorizing tenant access")
}
