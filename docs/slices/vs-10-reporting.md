# VS-10 · Reporting Engine

| Acceptance Criterion                                                          | Implementation |
|-------------------------------------------------------------------------------|----------------|
| All 11 report types can be generated for a test engagement                    | `reporting.AllReportTypes()` returns 11 codes; `reporting.Service.Generate` validates input |
| PDF contains partner logo, branded cover page, confidentiality marking        | HTML template renders `Branding.LogoURL`, `PrimaryColor`, `WatermarkText`, `ConfidentialityTag` |
| All 6 export formats produced correctly                                       | `reporting.AllFormats()` returns `pdf, docx, xlsx, html, json, csv`; per-format render branches |
| Compliance report correctly maps findings to ISO 27001 controls               | `reporting.mapCompliance` populates `ISO27001`, `PCIDSS`, `SOC2` maps based on scan_type |
| Report download logged in `report_download_logs` with user and timestamp      | `reporting.LogDownload` writes the row; called from the download handler |
| White-label partner report contains zero ZAISHIELD branding                    | Template only references the branding bundle resolved by partner_id; default is overridden |

## Key files

- `backend/migrations/0008_retesting_reporting.up.sql`
- `backend/internal/reporting/service.go`
- `frontend/src/pages/Reports.tsx`
