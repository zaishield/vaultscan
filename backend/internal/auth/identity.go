// Package auth provides identity, JWT validation, and RBAC enforcement.
//
// In production the gateway enforces token validation against Keycloak (OIDC).
// Locally we accept HS256-signed tokens minted by the platform for tests.
package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Identity is the authenticated principal attached to every request.
type Identity struct {
	UserID      uuid.UUID
	Email       string
	FullName    string
	PlatformID  uuid.UUID
	PartnerID   *uuid.UUID
	TenantID    *uuid.UUID
	Roles       []string         // role codes
	Permissions map[string]bool  // permission codes
	MFAVerified bool
}

func (i *Identity) Has(permission string) bool {
	if i == nil {
		return false
	}
	if i.HasRole("zaishield_super_admin") {
		return true
	}
	return i.Permissions[permission]
}

func (i *Identity) HasRole(code string) bool {
	if i == nil {
		return false
	}
	for _, r := range i.Roles {
		if r == code {
			return true
		}
	}
	return false
}

type ctxKey int

const identityKey ctxKey = 1

func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// FromContext returns the identity attached to ctx, or an error if none.
func FromContext(ctx context.Context) (*Identity, error) {
	v := ctx.Value(identityKey)
	id, ok := v.(*Identity)
	if !ok || id == nil {
		return nil, errors.New("auth: no identity in context")
	}
	return id, nil
}
