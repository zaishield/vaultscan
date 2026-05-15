# VS-02 · Partner & White-Label Engine

| Acceptance Criterion                                                                  | Implementation |
|---------------------------------------------------------------------------------------|----------------|
| Three partner domains each display distinct branding without code change              | `partner_domains` + `partner_branding` tables + `branding.ResolveByDomain` in `backend/internal/branding/service.go` |
| White-label partner sees zero ZAISHIELD branding in portal, emails, or reports        | Frontend resolves branding from `/api/v1/branding`; reports built from `partner_branding` row, not hardcoded |
| Report cover page renders partner logo, colors, and legal footer                      | `backend/internal/reporting/service.go` HTML template uses `Branding.{LogoURL,PrimaryColor,LegalFooter,WatermarkText}` |
| Feature flags restrict portal modules per partner                                     | `partner_feature_flags` table + `branding.SetFeatureFlag`; bundle exposes flags to UI |
| Partner admin updates branding and sees live result within 60 seconds                 | `PUT /api/v1/partners/{id}/branding` + `frontend/src/pages/Settings.tsx` reload on save |

## Tables (Blueprint §20.2)

`partner_branding`, `partner_domains`, `partner_email_templates`,
`partner_report_templates`, `partner_billing_plans`, `partner_feature_flags`,
`partner_support_settings`.

## Key files

- `backend/migrations/0002_partners_branding.up.sql`
- `backend/migrations/0011_zaishield_brand.up.sql` (seed brand applied)
- `backend/internal/branding/service.go`
- `frontend/src/store/branding.ts`
- `frontend/src/components/ui/Logo.tsx` (theme-aware, partner-override-aware)
