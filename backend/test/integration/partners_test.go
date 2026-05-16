//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/partners"
)

// Partners service is the spine of multi-tier reseller hierarchy
// (ZAISHIELD → Distributor → Reseller → Tenant) and was previously only
// exercised transitively through HTTP wiring tests. These direct tests
// pin behaviour at the service boundary so a regression in the SQL or
// audit/event side-effects shows up loudly.

func TestPartners_Create_Distributor(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	ctx := context.Background()

	p, err := svc.Create(ctx, &adminID, partners.CreateInput{
		PlatformID: platformID,
		TypeCode:   "distributor",
		Name:       "Acme Distributors",
		Slug:       "acme-distrib-" + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatalf("create distributor: %v", err)
	}
	if p.ID == uuid.Nil {
		t.Fatal("distributor ID should not be nil")
	}
	if p.Status != "active" {
		t.Errorf("status=%q want active", p.Status)
	}
	if p.TypeCode != "distributor" {
		t.Errorf("type=%q want distributor", p.TypeCode)
	}

	// Branding stub must exist so the portal always has something to render.
	var brandRows int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM partner_branding WHERE partner_id=$1`, p.ID).Scan(&brandRows); err != nil {
		t.Fatalf("count branding: %v", err)
	}
	if brandRows != 1 {
		t.Errorf("branding rows=%d want 1", brandRows)
	}

	// Support settings stub must exist.
	var supportRows int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM partner_support_settings WHERE partner_id=$1`, p.ID).Scan(&supportRows); err != nil {
		t.Fatalf("count support: %v", err)
	}
	if supportRows != 1 {
		t.Errorf("support rows=%d want 1", supportRows)
	}

	// Roundtrip via Get.
	got, err := svc.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != p.Name {
		t.Errorf("Get returned name=%q want %q", got.Name, p.Name)
	}
}

func TestPartners_Create_ResellerLinksToDistributor(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	ctx := context.Background()

	distrib, err := svc.Create(ctx, &adminID, partners.CreateInput{
		PlatformID: platformID,
		TypeCode:   "distributor",
		Name:       "Parent Distrib",
		Slug:       "parent-d-" + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatalf("create distributor: %v", err)
	}
	reseller, err := svc.Create(ctx, &adminID, partners.CreateInput{
		PlatformID: platformID,
		ParentID:   &distrib.ID,
		TypeCode:   "reseller",
		Name:       "Child Reseller",
		Slug:       "child-r-" + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	// The mapping row makes the hierarchy query work.
	var mapped int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM partner_reseller_mapping
		  WHERE distributor_id=$1 AND reseller_id=$2`, distrib.ID, reseller.ID).Scan(&mapped); err != nil {
		t.Fatalf("count mapping: %v", err)
	}
	if mapped != 1 {
		t.Errorf("partner_reseller_mapping rows=%d want 1", mapped)
	}
}

func TestPartners_Create_RejectsInvalidType(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	if _, err := svc.Create(context.Background(), &adminID, partners.CreateInput{
		PlatformID: platformID,
		TypeCode:   "bogus-type-code",
		Name:       "x",
		Slug:       "x",
	}); err == nil {
		t.Fatal("create with unknown type should error")
	}
}

func TestPartners_Create_RejectsMissingFields(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	ctx := context.Background()
	cases := []partners.CreateInput{
		{PlatformID: platformID, TypeCode: "distributor", Name: "", Slug: "s"},
		{PlatformID: platformID, TypeCode: "distributor", Name: "n", Slug: ""},
		{PlatformID: platformID, TypeCode: "", Name: "n", Slug: "s"},
	}
	for i, in := range cases {
		if _, err := svc.Create(ctx, &adminID, in); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestPartners_Get_NotFound(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	if _, err := svc.Get(context.Background(), uuid.New()); err != partners.ErrNotFound {
		t.Errorf("got %v want ErrNotFound", err)
	}
}

func TestPartners_List_FiltersByPlatform(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	ctx := context.Background()
	_, err := svc.Create(ctx, &adminID, partners.CreateInput{
		PlatformID: platformID, TypeCode: "distributor",
		Name: "ListA", Slug: "lista-" + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatal(err)
	}
	// Distractor on a different platform must not appear.
	otherPlatform := uuid.New()
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO platforms(id, name, slug) VALUES ($1, 'other', $2)
		 ON CONFLICT DO NOTHING`,
		otherPlatform, "other-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("seed platform: %v", err)
	}
	if _, err := svc.Create(ctx, &adminID, partners.CreateInput{
		PlatformID: otherPlatform, TypeCode: "distributor",
		Name: "ListB", Slug: "listb-" + uuid.NewString()[:8],
	}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.List(ctx, platformID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p.PlatformID != platformID {
			t.Errorf("List returned cross-platform partner %s with platform %s",
				p.ID, p.PlatformID)
		}
	}
}

func TestPartners_HierarchyForTenant_DirectChain(t *testing.T) {
	h := newHarness(t)
	svc := partners.New(h.pool, h.audit, h.bus)
	// The harness seeds tenants under directID — which is created in
	// migration 0010 as a "direct" partner type. HierarchyForTenant
	// should return Platform set, and Partner = the direct partner's
	// name (no distributor / reseller chain).
	tenantID, _ := h.makeTenant(t, "hier-direct-"+uuid.NewString()[:6])
	hi, err := svc.HierarchyForTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("hierarchy: %v", err)
	}
	if hi.Platform == "" || hi.Partner == "" {
		t.Errorf("hierarchy missing platform/partner: %+v", hi)
	}
}
