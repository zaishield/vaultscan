// Package api wires services to HTTP routes per Blueprint §21.
package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/guardrails"
	"github.com/zaishield/vaultscan/backend/internal/authdocs"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/cosign"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/email"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
	"github.com/zaishield/vaultscan/backend/internal/observability"
	"github.com/zaishield/vaultscan/backend/internal/partners"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
	"github.com/zaishield/vaultscan/backend/internal/users"
)

// Services aggregates everything the API server needs.
type Services struct {
	Pool         *pgxpool.Pool
	Cfg          *config.Config
	Log          zerolog.Logger
	Verifier     *auth.Verifier
	Audit        *audit.Service
	Bus          *eventbus.Bus
	Branding     *branding.Service
	Tenants      *tenants.Service
	Partners     *partners.Service
	Engagements  *engagements.Service
	AuthDocs     *authdocs.Service
	Assets       *assets.Service
	Scope        *scopeguard.Service
	ScanOrch     *scanorch.Orchestrator
	Signer       *scanorch.Signer  // exposed so /api/v1/orchestrator/public-key can serve PEM
	Agents       *agents.Service
	Findings     *findings.Service
	Vault        *evidence.Vault
	Retests      *retesting.Service
	Reports      *reporting.Service
	Integrations *integrations.Service
	Dashboards   *dashboards.Service
	Users        *users.Service
	Email        *email.Service
	Cosign       *cosign.Service
	BrandAssets  *branding.AssetService

	// Deepened service surface (VS-05..VS-12 + HS-01/HS-02/HS-05).
	Nodes        *scanorch.NodeOps
	LiveStream   *dashboards.LiveStream
	Guardrails   *guardrails.Service
	Bruteforce   *auth.BruteforceShield

	// HS-01 / MFA + JWKS deepening.
	MFA  *auth.MFAService
	Keys *auth.KeyManager
}

// Mount returns a fully wired HTTP router.
func Mount(s *Services) http.Handler {
	r := chi.NewRouter()
	r.Use(chiware.Recoverer)
	r.Use(middleware.RequestID())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.MaxBodySize(32 << 20)) // 32 MiB cap on any request body
	r.Use(observability.HTTPDurationMiddleware)

	cors := cors.New(cors.Options{
		AllowedOrigins:   s.Cfg.CORSAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Tenant-Id", "X-Request-Id"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	r.Use(cors.Handler)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// /metrics is mounted before the auth group so Prometheus can scrape
	// without a token. Network policy restricts the scrape source to the
	// monitoring namespace (Blueprint §27.1).
	r.Handle("/metrics", observability.PromHandler())
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*1e9)
		defer cancel()
		if err := s.Pool.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "db down", "err": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})

	// Public branding endpoint (Blueprint §8.5)
	r.Get("/api/v1/branding", brandingByDomain(s))
	r.Post("/api/v1/auth/dev-token", devToken(s))

	// JWKS — public so external token consumers can fetch the active
	// + verify_only RSA public keys without auth (RFC 7517 norm).
	r.Get("/.well-known/jwks.json", jwksHandler(s))
	r.Get("/api/v1/.well-known/jwks.json", jwksHandler(s))

	// MFA second-step verify is reachable without a full JWT — the
	// caller has just completed password auth and holds a short-lived
	// challenge token. The MFA service does its own user-id check.
	r.Post("/api/v1/auth/mfa/verify", mfaVerify(s))

	// Public cloud public key. Scanner workers and internal agents fetch
	// this on bootstrap to verify per-job signatures (Blueprint §11.3,
	// §13.5). The endpoint is read-only and serves a PEM-encoded
	// SubjectPublicKeyInfo so callers can validate without any client.
	r.Get("/api/v1/orchestrator/public-key", orchestratorPublicKey(s))

	// All authenticated endpoints
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(func(req *http.Request) (*auth.Identity, error) {
			tok := req.Header.Get("Authorization")
			if tok == "" {
				return nil, errors.New("missing Authorization header")
			}
			return s.Verifier.Parse(req.Context(), tok)
		}))
		r.Use(middleware.TenantScope("X-Tenant-Id"))
		// TenantBinding pre-sets the Postgres GUC so RLS policies engage
		// for the lifetime of this request. Must come AFTER Auth and
		// TenantScope so the identity is resolved before we bind.
		r.Use(middleware.TenantBinding(s.Pool))
		// Rate limiting: pluggable backend selected by config.
		//   memory → single-pod sync.Map token bucket
		//   redis  → cross-pod sliding-window counter (atomic Lua EVAL)
		// Production guard refuses to boot with backend=memory.
		var limiter middleware.Limiter
		switch s.Cfg.RateLimitBackend {
		case "redis":
			rl, err := middleware.NewRedisLimiter(
				s.Cfg.RateLimitRedisAddr,
				s.Cfg.RateLimitRedisPassword,
				s.Cfg.RateLimitRedisDB,
			)
			if err == nil {
				limiter = rl
			} else {
				limiter = middleware.NewInMemoryLimiter()
			}
		default:
			limiter = middleware.NewInMemoryLimiter()
		}
		windowSec := s.Cfg.RateLimitWindowSec
		if windowSec <= 0 {
			windowSec = 60
		}
		// Convert RPS-style config into limit-over-window: configured
		// RPS × window = total requests allowed in the rolling window.
		mid := middleware.NewRateLimitMiddleware(limiter, s.Cfg.RateLimitRPS*windowSec, windowSec)
		r.Use(mid.Wrap)

		// Tenants
		r.Route("/api/v1/tenants", func(r chi.Router) {
			r.With(middleware.RequirePermission("create_tenant")).
				Post("/", createTenant(s))
			r.Get("/", listTenants(s))
			r.Get("/{tenant_id}", getTenant(s))
			r.With(middleware.RequirePermission("create_tenant")).
				Post("/{tenant_id}/suspend", suspendTenant(s))
			r.With(middleware.RequirePermission("create_tenant")).
				Post("/{tenant_id}/reactivate", reactivateTenant(s))
		})

		// Effective identity + session management (VS-01 hardening).
		r.Get("/api/v1/auth/me", whoAmI(s))
		r.Post("/api/v1/auth/logout", logoutAndRevoke(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/users/{user_id}/revoke-tokens", revokeUserTokens(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/users/{user_id}/unlock", unlockUser(s))
		// Partners
		r.Route("/api/v1/partners", func(r chi.Router) {
			r.With(middleware.RequirePermission("create_partner")).
				Post("/", createPartner(s))
			r.Get("/", listPartners(s))
			r.Get("/{partner_id}", getPartner(s))
			r.With(middleware.RequirePermission("manage_branding")).
				Put("/{partner_id}/branding", updateBranding(s))
			r.Get("/{partner_id}/hierarchy/tenant/{tenant_id}", hierarchyForTenant(s))
			r.With(middleware.RequirePermission("manage_branding")).
				Post("/{partner_id}/domains", addPartnerDomain(s))
		})

		// Engagements + Scope + Authorization
		r.Route("/api/v1/engagements", func(r chi.Router) {
			r.With(middleware.RequirePermission("create_engagement")).
				Post("/", createEngagement(s))
			r.Get("/{engagement_id}", getEngagement(s))
			r.Get("/", listEngagements(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Post("/{engagement_id}/activate", activateEngagement(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Post("/{engagement_id}/pause", pauseEngagement(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Post("/{engagement_id}/resume", resumeEngagement(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Post("/{engagement_id}/rate-limit", setEngagementRateLimit(s))
			r.With(middleware.RequirePermission("download_evidence"), middleware.RequireMFA()).
				Get("/{engagement_id}/authorization/{document_id}/view", viewAuthDoc(s))
		})
		r.Route("/api/v1/scope", func(r chi.Router) {
			r.With(middleware.RequirePermission("create_engagement")).
				Post("/", addScope(s))
			r.With(middleware.RequirePermission("create_engagement")).
				Post("/import-csv", importScopeCSV(s))
			r.Get("/{engagement_id}", listScope(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Post("/{scope_id}/approve", approveScope(s))
		})
		r.Route("/api/v1/authorization", func(r chi.Router) {
			r.With(middleware.RequirePermission("upload_authorization")).
				Post("/{engagement_id}", uploadAuthDoc(s))
		})

		// Assets
		r.Route("/api/v1/assets", func(r chi.Router) {
			r.Post("/", createAsset(s))
			r.Get("/", listAssets(s))
			r.Post("/import-csv", importAssetsCSV(s))
			r.Post("/bulk", bulkAssets(s))
			r.Get("/{asset_id}/risk-score", assetRiskScore(s))
		})

		// Scans
		r.Route("/api/v1/scans", func(r chi.Router) {
			r.Get("/profiles", listScanProfiles(s))
			r.With(middleware.RequirePermission("create_scan_job")).
				Post("/external", submitExternalScan(s))
			r.With(middleware.RequirePermission("create_scan_job")).
				Post("/internal", submitInternalScan(s))
			r.Get("/{scan_id}", getScan(s))
			r.Get("/", listScans(s))
			r.With(middleware.RequirePermission("approve_aggressive_scan")).
				Post("/{scan_id}/approve", approveScan(s))
			r.With(middleware.RequirePermission("trigger_emergency_stop")).
				Post("/emergency-stop", emergencyStop(s))
		})

		// Agents
		r.Route("/api/v1/agents", func(r chi.Router) {
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/", provisionAgent(s))
			r.Get("/", listAgents(s))
			r.Get("/{agent_id}", getAgent(s))
			r.Get("/{agent_id}/policy", getAgentPolicy(s))
			r.With(middleware.RequirePermission("manage_agents")).
				Put("/{agent_id}/policy", updateAgentPolicy(s))
			// Cert rotation: issues a fresh enrollment token + revokes the
			// agent's current certificate. Agent's update channel detects
			// the rotation and submits a new CSR via the agent-gateway
			// enroll endpoint with the new token.
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/{agent_id}/rotate-cert", rotateAgentCert(s))
		})

		// Findings
		r.Route("/api/v1/findings", func(r chi.Router) {
			r.Get("/", listFindings(s))
			r.Get("/{finding_id}", getFinding(s))
			r.With(middleware.RequirePermission("edit_findings")).
				Patch("/{finding_id}", patchFinding(s))
			r.With(middleware.RequirePermission("edit_findings")).
				Post("/bulk", bulkPatchFindings(s))
			r.Get("/{finding_id}/comments", listFindingComments(s))
			r.With(middleware.RequirePermission("edit_findings")).
				Post("/{finding_id}/comments", addFindingComment(s))
			r.With(middleware.RequirePermission("view_audit_logs")).
				Get("/sla-breaches", findingSLABreaches(s))
		})

		// Evidence
		r.Route("/api/v1/evidence", func(r chi.Router) {
			r.With(middleware.RequirePermission("download_evidence"), middleware.RequireMFA()).
				Get("/{evidence_id}", evidenceMeta(s))
			r.With(middleware.RequirePermission("download_evidence")).
				Post("/manual", manualEvidenceUpload(s))
			r.With(middleware.RequirePermission("download_evidence"), middleware.RequireMFA()).
				Get("/{evidence_id}/url", signedDownloadURL(s))
			r.Get("/{evidence_id}/download", downloadEvidence(s))
		})

		// Retesting
		r.Route("/api/v1/retests", func(r chi.Router) {
			r.With(middleware.RequirePermission("request_retest")).
				Post("/", requestRetest(s))
			r.With(middleware.RequirePermission("execute_retest")).
				Post("/{retest_id}/launch", launchRetestScan(s))
			r.With(middleware.RequirePermission("execute_retest")).
				Post("/{retest_id}/result", recordRetestResult(s))
			r.Get("/findings/{finding_id}", listRetestsForFinding(s))
			r.Get("/queue", retestQueueForUser(s))
		})

		// Reports
		r.Route("/api/v1/reports", func(r chi.Router) {
			r.With(middleware.RequirePermission("generate_report")).
				Post("/", generateReport(s))
			r.Get("/{report_id}", getReport(s))
		})

		// Integrations
		r.Route("/api/v1/integrations", func(r chi.Router) {
			r.Get("/", listIntegrations(s))
			r.Post("/{type}", createIntegration(s))
		})

		// Dashboards (with time-range + drill-down)
		r.Route("/api/v1/dashboards", func(r chi.Router) {
			r.Get("/executive", execDashboard(s))
			r.Get("/technical", techDashboard(s))
			r.Get("/partner", partnerDashboard(s))
			r.Get("/findings/critical", drillCriticalFindings(s))
			r.Get("/findings/sla-breaches", drillSLABreaches(s))
			r.Get("/scans/recent", drillRecentScans(s))
		})

		// Users + role assignment (VS-01)
		r.Route("/api/v1/users", func(r chi.Router) {
			r.Get("/", listUsers(s))
			r.With(middleware.RequirePermission("create_tenant")).
				Post("/", createUser(s))
			r.Get("/{user_id}", getUser(s))
			r.Get("/{user_id}/roles", listUserRoles(s))
			r.With(middleware.RequirePermission("create_tenant")).
				Post("/{user_id}/roles", assignUserRole(s))
			r.With(middleware.RequirePermission("create_tenant")).
				Delete("/{user_id}/roles/{role_code}", revokeUserRole(s))
		})

		// White-label email templates (VS-02)
		r.Route("/api/v1/partners/{partner_id}/email-templates", func(r chi.Router) {
			r.Get("/", listEmailTemplates(s))
			r.With(middleware.RequirePermission("manage_branding")).
				Put("/{code}", upsertEmailTemplate(s))
			r.With(middleware.RequirePermission("manage_branding")).
				Post("/{code}/send-test", sendTestEmail(s))
		})

		// VS-02 deepening: brand asset upload + DNS posture + preview
		r.Route("/api/v1/partners/{partner_id}/brand-assets", func(r chi.Router) {
			r.Get("/", listBrandAssets(s))
			r.With(middleware.RequirePermission("manage_branding")).
				Post("/{asset_type}", uploadBrandAsset(s))
		})
		r.With(middleware.RequirePermission("manage_branding")).
			Post("/api/v1/partners/{partner_id}/sender-dns/check", checkSenderDNS(s))
		r.Get("/api/v1/partners/{partner_id}/preview", brandingPreview(s))

		// Rules of engagement + blackouts (VS-03)
		r.Route("/api/v1/engagements/{engagement_id}/roe", func(r chi.Router) {
			r.Get("/", getRoE(s))
			r.With(middleware.RequirePermission("approve_scope")).
				Put("/", upsertRoE(s))
		})

		// Report approval workflow (VS-10)
		r.With(middleware.RequirePermission("generate_report")).
			Post("/api/v1/reports/{report_id}/approve", approveReport(s))

		// Integration test + health (VS-11)
		r.Route("/api/v1/integrations/{integration_id}", func(r chi.Router) {
			r.Post("/test", testIntegration(s))
		})
		r.Get("/api/v1/integration-health", integrationHealth(s))

		// Audit
		r.Route("/api/v1/audit", func(r chi.Router) {
			r.With(middleware.RequirePermission("view_audit_logs")).Get("/", listAudit(s))
			r.With(middleware.RequirePermission("view_audit_logs")).Get("/verify", verifyAudit(s))
			// HS-02 deepening
			r.With(middleware.RequirePermission("view_audit_logs")).Get("/verify-deep", verifyAuditDeep(s))
			r.With(middleware.RequirePermission("view_audit_logs")).Get("/timeline", auditTimeline(s))
			r.With(middleware.RequirePermission("view_audit_logs")).Get("/retention-policies", retentionPolicies(s))
			r.With(middleware.RequirePermission("view_audit_logs")).
				Post("/ship/{integration_id}", shipAuditBatch(s))
		})

		// ===================================================================
		// VS-05 Scanner ops
		// ===================================================================
		r.Route("/api/v1/scanner", func(r chi.Router) {
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/nodes/{node_id}/heartbeat", recordScannerHeartbeat(s))
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/nodes/failover-sweep", sweepStalledNodes(s))
			r.Get("/regions/{region}/quota", getRegionQuota(s))
			r.With(middleware.RequirePermission("manage_agents")).
				Put("/regions/{region}/quota", setRegionQuota(s))
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/regions/{region}/pull-credentials", upsertPullCredential(s))
			r.Get("/regions/{region}/network-policy.yaml", renderNetworkPolicy(s))
		})

		// ===================================================================
		// VS-06 Agent ops
		// ===================================================================
		r.Route("/api/v1/agents/{agent_id}/csr", func(r chi.Router) {
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/", submitAgentCSR(s))
		})
		r.With(middleware.RequirePermission("manage_agents")).
			Post("/api/v1/agents/{agent_id}/telemetry/rollup", rollupAgentTelemetry(s))
		r.Get("/api/v1/agents/{agent_id}/telemetry", listAgentTelemetry(s))
		r.Route("/api/v1/agent-updates", func(r chi.Router) {
			r.With(middleware.RequirePermission("manage_agents")).
				Post("/", publishAgentBundle(s))
		})
		r.Get("/api/v1/agents/{agent_id}/update-offer", offerAgentUpdate(s))
		r.With(middleware.RequirePermission("trigger_emergency_stop")).
			Post("/api/v1/agents/{agent_id}/emergency-stop", requestAgentEmergencyStop(s))
		r.Post("/api/v1/emergency-stops/{stop_id}/ack", ackAgentEmergencyStop(s))
		r.Get("/api/v1/agents/{agent_id}/emergency-stop-sla", emergencyStopSLA(s))

		// ===================================================================
		// VS-07 Findings ops
		// ===================================================================
		r.Get("/api/v1/findings/clusters", listFindingClusters(s))
		r.With(middleware.RequirePermission("edit_findings")).
			Post("/api/v1/findings/severity-overrides", addSeverityOverride(s))
		r.With(middleware.RequirePermission("edit_findings")).
			Post("/api/v1/findings/suppression-rules", addSuppressionRule(s))
		r.Get("/api/v1/findings/export.sarif", sarifExport(s))

		// ===================================================================
		// VS-08 Evidence ops
		// ===================================================================
		r.With(middleware.RequirePermission("download_evidence")).
			Post("/api/v1/evidence/{evidence_id}/integrity", verifyEvidenceIntegrity(s))
		r.With(middleware.RequirePermission("download_evidence"), middleware.RequireMFA()).
			Post("/api/v1/evidence/{evidence_id}/worm", enableEvidenceWORM(s))
		r.With(middleware.RequirePermission("download_evidence")).
			Get("/api/v1/evidence/{evidence_id}/chain-of-custody", chainOfCustody(s))
		r.With(middleware.RequirePermission("download_evidence")).
			Get("/api/v1/evidence/{evidence_id}/chain-of-custody.md", chainOfCustodyMarkdown(s))
		r.With(middleware.RequirePermission("create_tenant"), middleware.RequireMFA()).
			Post("/api/v1/tenants/{tenant_id}/data-key/rotate", rotateTenantKey(s))
		r.With(middleware.RequirePermission("download_evidence")).
			Post("/api/v1/evidence/upload-dek", uploadEvidenceWithDEK(s))

		// ===================================================================
		// VS-09 Retesting ops
		// ===================================================================
		r.With(middleware.RequirePermission("request_retest")).
			Post("/api/v1/findings/{finding_id}/auto-retest", autoLaunchRetest(s))
		r.With(middleware.RequirePermission("request_retest")).
			Post("/api/v1/retest-batches", createRetestBatch(s))
		r.Get("/api/v1/retest-batches/{batch_id}", getRetestBatch(s))
		r.With(middleware.RequirePermission("execute_retest")).
			Patch("/api/v1/retest-batches/{batch_id}/items/{retest_id}", markRetestBatchItem(s))
		r.Get("/api/v1/retests/{retest_id}/diff", getRetestDiff(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Put("/api/v1/settings/auto-retest", setAutoRetest(s))

		// ===================================================================
		// VS-10 Reporting ops
		// ===================================================================
		r.With(middleware.RequirePermission("generate_report")).
			Post("/api/v1/report-schedules", createReportSchedule(s))
		r.With(middleware.RequirePermission("generate_report")).
			Post("/api/v1/report-schedules/run-due", runDueReports(s))
		r.Get("/api/v1/compliance/{framework}/engagements/{engagement_id}", complianceMatrix(s))
		r.Get("/api/v1/compliance/{framework}/engagements/{engagement_id}.md", complianceMatrixMarkdown(s))

		// ===================================================================
		// VS-11 Integration DLQ
		// ===================================================================
		r.Get("/api/v1/integrations/{integration_id}/dead-letters", listDeadLetters(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/integrations/dead-letters/{dlq_id}/replay", replayDeadLetter(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/integrations/dead-letters/{dlq_id}/resolve", resolveDeadLetter(s))

		// ===================================================================
		// VS-12 Dashboard ops
		// ===================================================================
		r.Get("/api/v1/dashboards/layouts", listDashboardLayouts(s))
		r.Post("/api/v1/dashboards/layouts", saveDashboardLayout(s))
		r.Get("/api/v1/dashboards/geo", geoScanNodes(s))
		r.Get("/api/v1/dashboards/compliance", complianceSnapshot(s))
		r.Get("/api/v1/dashboards/stream", dashboardStreamSSE(s))

		// ===================================================================
		// HS-01 Auth hardening
		// ===================================================================
		r.With(middleware.RequirePermission("view_audit_logs")).
			Get("/api/v1/auth/ip-lockouts", listIPLockouts(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/auth/ip-lockouts/{ip}/unlock", unlockIP(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Post("/api/v1/auth/compromised-passwords/{prefix}", loadCompromisedPasswords(s))

		// ===================================================================
		// HS-05 Guardrails
		// ===================================================================
		r.Get("/api/v1/platform/maintenance", maintenanceStatus(s))
		r.With(middleware.RequirePermission("create_tenant")).
			Put("/api/v1/platform/maintenance", setMaintenance(s))
		r.With(middleware.RequirePermission("create_tenant"), middleware.RequireMFA()).
			Post("/api/v1/platform/break-glass", issueBreakGlass(s))
		r.Post("/api/v1/platform/break-glass/redeem", redeemBreakGlass(s))
		r.Get("/api/v1/platform/policy-rules", listPolicyRules(s))

		// MFA enrolment + management (HS-01).
		r.Post("/api/v1/auth/mfa/enroll/start", mfaEnrollStart(s))
		r.Post("/api/v1/auth/mfa/enroll/confirm", mfaEnrollConfirm(s))
		r.With(middleware.RequireMFA()).
			Delete("/api/v1/auth/mfa", mfaDisable(s))

		// JWT key rotation (admin only, MFA-gated).
		r.With(middleware.RequirePermission("create_tenant"), middleware.RequireMFA()).
			Post("/api/v1/auth/jwt-keys/rotate", rotateJWTKey(s))

		// §24 Mobile portal — thin surface for iOS / Android.
		// All routes require authentication; emergency-stop adds MFA.
		r.Post("/api/v1/mobile/devices", enrollMobileDevice(s))
		r.Delete("/api/v1/mobile/devices/{device_id}", revokeMobileDevice(s))
		r.Get("/api/v1/mobile/dashboard", mobileDashboard(s))
		r.Post("/api/v1/mobile/alerts/ack", mobileAckAlert(s))
		r.With(middleware.RequirePermission("trigger_emergency_stop"), middleware.RequireMFA()).
			Post("/api/v1/mobile/emergency-stop", mobileEmergencyStop(s))

		// §33 Customer feedback. Any authenticated user can submit;
		// listing + triage gated to view_audit_logs (admins).
		r.Post("/api/v1/feedback", submitFeedback(s))
		r.Post("/api/v1/feedback/dismiss-nps", dismissNPSPrompt(s))
		r.With(middleware.RequirePermission("view_audit_logs")).
			Get("/api/v1/feedback", listFeedback(s))
		r.With(middleware.RequirePermission("view_audit_logs")).
			Patch("/api/v1/feedback/{feedback_id}", triageFeedback(s))

		// §34 Partner integration marketplace.
		r.Get("/api/v1/marketplace/listings", listMarketplaceListings(s))
		r.With(middleware.RequirePermission("manage_branding")).
			Post("/api/v1/marketplace/installs", installFromMarketplace(s))
		r.With(middleware.RequirePermission("manage_branding")).
			Patch("/api/v1/marketplace/installs/{install_id}", configureMarketplaceInstall(s))
		r.With(middleware.RequirePermission("manage_branding")).
			Delete("/api/v1/marketplace/installs/{install_id}", uninstallMarketplaceInstall(s))
		r.Get("/api/v1/marketplace/installs", listMarketplaceInstalls(s))
	})

	return r
}
