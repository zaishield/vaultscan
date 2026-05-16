package auth

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAuthorizeTargetTenant_PlatformAdmin_AnyTenant(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: []string{"platform_admin"}}
	target := uuid.New()
	got, err := AuthorizeTargetTenant(id, target.String())
	if err != nil {
		t.Fatalf("platform admin should be allowed: %v", err)
	}
	if got != target {
		t.Errorf("got %s, want %s", got, target)
	}
}

func TestAuthorizeTargetTenant_PlatformAdmin_RequiresExplicit(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: []string{"platform_admin"}}
	if _, err := AuthorizeTargetTenant(id, ""); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("platform admin needs explicit tenant; got %v", err)
	}
}

func TestAuthorizeTargetTenant_TenantAdmin_OwnTenantOnly(t *testing.T) {
	t.Parallel()
	own := uuid.New()
	id := &Identity{Roles: []string{"tenant_admin"}, TenantID: &own}

	if got, err := AuthorizeTargetTenant(id, own.String()); err != nil || got != own {
		t.Errorf("own tenant should pass: got=%s err=%v", got, err)
	}
	if got, err := AuthorizeTargetTenant(id, ""); err != nil || got != own {
		t.Errorf("blank tenant should default to own: got=%s err=%v", got, err)
	}
	other := uuid.New()
	if _, err := AuthorizeTargetTenant(id, other.String()); !errors.Is(err, ErrCrossTenantForbidden) {
		t.Errorf("cross-tenant should be forbidden; got %v", err)
	}
}

func TestAuthorizeTargetTenant_TenantViewer_OwnTenantOnly(t *testing.T) {
	t.Parallel()
	own := uuid.New()
	id := &Identity{Roles: []string{"tenant_viewer"}, TenantID: &own}
	other := uuid.New()
	if _, err := AuthorizeTargetTenant(id, other.String()); !errors.Is(err, ErrCrossTenantForbidden) {
		t.Errorf("tenant_viewer cross-tenant should be forbidden; got %v", err)
	}
}

func TestAuthorizeTargetTenant_PartnerAdmin_AnyTenantWithExplicit(t *testing.T) {
	t.Parallel()
	pid := uuid.New()
	id := &Identity{Roles: []string{"partner_admin"}, PartnerID: &pid}
	target := uuid.New()
	if got, err := AuthorizeTargetTenant(id, target.String()); err != nil || got != target {
		t.Errorf("partner admin should reach any tenant when explicit: %s err=%v", got, err)
	}
	if _, err := AuthorizeTargetTenant(id, ""); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("partner admin needs explicit tenant; got %v", err)
	}
}

func TestAuthorizeTargetTenant_NoIdentity(t *testing.T) {
	t.Parallel()
	if _, err := AuthorizeTargetTenant(nil, uuid.New().String()); err == nil {
		t.Error("nil identity should reject")
	}
}

func TestAuthorizeTargetTenant_RejectsMalformedUUID(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: []string{"platform_admin"}}
	if _, err := AuthorizeTargetTenant(id, "not-a-uuid"); err == nil {
		t.Error("malformed UUID should reject")
	}
}

func TestAuthorizeTargetTenant_RejectsNoRoles(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: nil}
	if _, err := AuthorizeTargetTenant(id, uuid.New().String()); err == nil {
		t.Error("no roles should reject")
	}
}

func TestAuthorizeOptionalTenant_TenantAdmin_CrossTenantRejected(t *testing.T) {
	t.Parallel()
	own := uuid.New()
	other := uuid.New()
	id := &Identity{Roles: []string{"tenant_admin"}, TenantID: &own}
	if _, err := AuthorizeOptionalTenant(id, other.String()); !errors.Is(err, ErrCrossTenantForbidden) {
		t.Errorf("expected cross-tenant rejection; got %v", err)
	}
}

func TestAuthorizeOptionalTenant_PlatformAdmin_NilAllowed(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: []string{"platform_admin"}}
	got, err := AuthorizeOptionalTenant(id, "")
	if err != nil {
		t.Fatalf("platform admin nil should pass: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil tenant; got %v", got)
	}
}

func TestAuthorizeTargetTenant_SuperAdminCanCross(t *testing.T) {
	t.Parallel()
	id := &Identity{Roles: []string{"zaishield_super_admin"}}
	target := uuid.New()
	if got, err := AuthorizeTargetTenant(id, target.String()); err != nil || got != target {
		t.Errorf("super admin should pass: %v", err)
	}
}
