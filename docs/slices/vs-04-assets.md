# VS-04 · Asset Discovery & Management

| Acceptance Criterion                                                                          | Implementation |
|-----------------------------------------------------------------------------------------------|----------------|
| All 14 asset types can be created and retrieved                                               | `backend/internal/models/types.go` (`AssetTypes`) + `assets.Create` validates against the same list |
| CSV import of 500 assets completes without error and deduplicates correctly                   | `assets.ImportCSV` parses headers + reuses `Create` with idempotent upsert (UNIQUE(tenant_id, asset_type, value) → bump `last_seen`) |
| Asset criticality propagates to finding severity display                                       | Findings list joins assets via `asset_id`; `criticality` rendered with severity-style badges in `frontend/src/pages/Assets.tsx` |
| Assets scoped to engagement and tenant; no cross-tenant leakage                                | `assets.List` always filters on tenant_id; tenant header enforced by middleware |

## Key files

- `backend/migrations/0004_assets.up.sql`
- `backend/internal/assets/service.go`
- `frontend/src/pages/Assets.tsx`
