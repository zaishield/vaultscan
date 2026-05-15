//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/assets"
)

// TestVS04_SubfinderIngest: parsing a 3-line JSONL feed creates 3 new
// assets the first time and dedupes them on re-ingest.
func TestVS04_SubfinderIngest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "vs04-subfinder")

	feed := `{"host":"api.globex.example","source":"crtsh"}
{"host":"www.globex.example","source":"dns"}
{"host":"static.globex.example","source":"crtsh"}
`
	in := assets.IngestContext{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		EngagementID: &engagementID, Actor: &adminID,
	}
	created, skipped, err := h.assets.IngestSubfinder(ctx, in, strings.NewReader(feed))
	if err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	if created != 3 || skipped != 0 {
		t.Fatalf("expected 3 new / 0 skipped, got %d/%d", created, skipped)
	}

	// Re-ingest: same hosts → 0 new, 3 skipped (dedup hit).
	created2, skipped2, err := h.assets.IngestSubfinder(ctx, in, strings.NewReader(feed))
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if created2 != 0 || skipped2 != 3 {
		t.Fatalf("expected 0 new / 3 skipped on rerun, got %d/%d", created2, skipped2)
	}
}

// TestVS04_FuzzyDedup: 'WWW.Example.com' and 'example.com' collapse to the
// same dedup_key, so FuzzyDedupCandidates flags the collision.
func TestVS04_FuzzyDedup(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs04-fuzzy")

	if _, err := h.assets.Create(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		AssetType: "domain", Value: "Example.COM", Plane: "external",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	hits, err := h.assets.FuzzyDedupCandidates(ctx, tenantID, "domain", "www.example.com")
	if err != nil {
		t.Fatalf("fuzzy: %v", err)
	}
	if len(hits) != 1 || strings.ToLower(hits[0].Value) != "example.com" {
		t.Fatalf("expected fuzzy collision for www.example.com, got %+v", hits)
	}
}

// TestVS04_Relationships: link a parent domain to a subdomain and prove
// Children + Parents traverse the edge.
func TestVS04_Relationships(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs04-rel")
	parent, _ := h.assets.Create(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		AssetType: "domain", Value: "globex.example", Plane: "external",
	})
	child, _ := h.assets.Create(ctx, assets.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenantID,
		AssetType: "subdomain", Value: "api.globex.example", Plane: "external",
	})
	if err := h.assets.LinkAssets(ctx, &adminID, parent.ID, child.ID, "contains"); err != nil {
		t.Fatalf("link: %v", err)
	}

	kids, err := h.assets.Children(ctx, parent.ID)
	if err != nil {
		t.Fatalf("children: %v", err)
	}
	if len(kids) != 1 || kids[0].ID != child.ID {
		t.Fatalf("expected one child %s, got %+v", child.ID, kids)
	}

	parents, _ := h.assets.Parents(ctx, child.ID)
	if len(parents) != 1 || parents[0].ID != parent.ID {
		t.Fatalf("expected one parent %s, got %+v", parent.ID, parents)
	}

	// Self-link refused.
	if err := h.assets.LinkAssets(ctx, &adminID, parent.ID, parent.ID, "contains"); err == nil {
		t.Fatalf("self-link should be rejected")
	}

	// Unknown kind rejected.
	if err := h.assets.LinkAssets(ctx, &adminID, parent.ID, child.ID, "lol"); err == nil {
		t.Fatalf("unknown kind should be rejected")
	}

	_ = uuid.UUID{}
}
