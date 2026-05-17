//go:build integration

// Audit-log pagination via keyset cursor (before_id). Previously the
// listAudit handler capped at 200 rows with no cursor — operators
// running SOC2 evidence collection hit a hard wall at page 1. This
// test pins the contract: items[].id strictly descending, and
// next_before_id present when the page is full.

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

func TestAuditPagination_CursorWalksWholeChain(t *testing.T) {
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "audit-page-"+uuid.NewString()[:6])

	// Seed 25 audit rows so we span at least two pages at limit=10.
	for i := 0; i < 25; i++ {
		if err := h.audit.Record(ctx, audit.Entry{
			PlatformID: platformID, PartnerID: &directID, TenantID: &tenantID,
			ActorID: &adminID, ActorType: "user",
			Event: "test.pagination", TargetType: "test",
			TargetID: fmt.Sprintf("page-row-%02d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	tok := mintToken(t, tenantID)
	fetch := func(beforeID int64) ([]map[string]any, int64) {
		t.Helper()
		url := srv.URL + "/api/v1/audit?tenant_id=" + tenantID.String() +
			"&event=test.pagination&limit=10"
		if beforeID > 0 {
			url += fmt.Sprintf("&before_id=%d", beforeID)
		}
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Tenant-Id", tenantID.String())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		var parsed struct {
			Items        []map[string]any `json:"items"`
			NextBeforeID int64            `json:"next_before_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&parsed)
		return parsed.Items, parsed.NextBeforeID
	}

	// Page 1: should return 10 items + a cursor.
	items, next := fetch(0)
	if len(items) != 10 {
		t.Fatalf("page 1 size = %d want 10", len(items))
	}
	if next == 0 {
		t.Fatal("page 1 missing next_before_id (chain has 25 rows)")
	}
	// Strictly descending ids.
	var prev int64
	for i, it := range items {
		id, _ := it["id"].(float64)
		if i > 0 && int64(id) >= prev {
			t.Errorf("items not strictly descending at i=%d: id=%v prev=%d", i, id, prev)
		}
		prev = int64(id)
	}

	// Page 2: pass the cursor, expect 10 more items.
	items2, next2 := fetch(next)
	if len(items2) != 10 {
		t.Fatalf("page 2 size = %d want 10", len(items2))
	}
	if next2 == 0 {
		t.Fatal("page 2 missing next_before_id (5 more rows remain)")
	}
	// No overlap with page 1.
	page1IDs := map[int64]bool{}
	for _, it := range items {
		id, _ := it["id"].(float64)
		page1IDs[int64(id)] = true
	}
	for _, it := range items2 {
		id, _ := it["id"].(float64)
		if page1IDs[int64(id)] {
			t.Errorf("page 2 overlaps page 1 at id=%d", int64(id))
		}
	}

	// Page 3: tail (5 rows + no cursor).
	items3, next3 := fetch(next2)
	if len(items3) != 5 {
		t.Fatalf("page 3 size = %d want 5 (tail of 25)", len(items3))
	}
	if next3 != 0 {
		t.Errorf("page 3 should have empty next_before_id; got %d", next3)
	}
}
