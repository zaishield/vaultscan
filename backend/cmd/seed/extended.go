// extended.go — multi-tenant / multi-plan / multi-region seed
// fixtures. Built on top of the minimal demo in main.go to give
// QA / sales / training environments realistic data without
// requiring hand-crafted SQL.
//
// Toggled via -extended flag. Idempotent — re-runs are safe.
//
// Note on users + auth: the platform delegates all authentication
// to an external IdP (Keycloak in dev; SAML/OIDC in prod). The
// users table has NO password_hash column — `keycloak_sub` ties a
// user to the IdP. For local dev these seeded users authenticate
// via /api/v1/auth/dev-token (gated by env=development).

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// extendedSeed adds: real users (bcrypt-hashed), multiple tenants
// on different plans + regions, scan jobs in 3 states, integrations
// (Slack + Jira + SIEM), compliance evidence rows, recent audit
// rows, mobile devices, retest batch.
//
// Called from main when the -extended flag is set.
func extendedSeed(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	if err := seedExtraTenants(ctx, tx, ids); err != nil {
		return fmt.Errorf("extra tenants: %w", err)
	}
	if err := seedUsers(ctx, tx, ids); err != nil {
		return fmt.Errorf("users: %w", err)
	}
	if err := seedIntegrations(ctx, tx, ids); err != nil {
		return fmt.Errorf("integrations: %w", err)
	}
	if err := seedScanJobs(ctx, tx, ids); err != nil {
		return fmt.Errorf("scan jobs: %w", err)
	}
	if err := seedComplianceEvidence(ctx, tx, ids); err != nil {
		return fmt.Errorf("compliance evidence: %w", err)
	}
	if err := seedAuditLogs(ctx, tx, ids); err != nil {
		return fmt.Errorf("audit logs: %w", err)
	}
	if err := seedNotifications(ctx, tx, ids); err != nil {
		return fmt.Errorf("notifications: %w", err)
	}
	return nil
}

// seedIDs are the deterministic IDs main.go already created. Passed
// through so the extension wires its rows to the same fixtures.
type seedIDs struct {
	platformID    uuid.UUID
	distID        uuid.UUID
	msspID        uuid.UUID
	tenantID      uuid.UUID // Globex (existing)
	engagementID  uuid.UUID
	agentID       uuid.UUID
	// New tenants the extension creates.
	tenantInitech  uuid.UUID // EU residency, business plan
	tenantHooli    uuid.UUID // US residency, enterprise plan
	tenantRandD    uuid.UUID // APAC residency, starter plan
	engagementHooli uuid.UUID
	engagementInitech uuid.UUID
}

// fixedSeedIDs returns the same deterministic IDs main.go uses, with
// the additions for the extended fixtures.
func fixedSeedIDs() seedIDs {
	return seedIDs{
		platformID:        uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		distID:            uuid.MustParse("00000000-0000-0000-0000-0000000000d1"),
		msspID:            uuid.MustParse("00000000-0000-0000-0000-0000000000d2"),
		tenantID:          uuid.MustParse("00000000-0000-0000-0000-000000000c01"),
		engagementID:      uuid.MustParse("00000000-0000-0000-0000-000000000e01"),
		agentID:           uuid.MustParse("00000000-0000-0000-0000-000000000a01"),
		tenantInitech:     uuid.MustParse("00000000-0000-0000-0000-000000000c10"),
		tenantHooli:       uuid.MustParse("00000000-0000-0000-0000-000000000c11"),
		tenantRandD:       uuid.MustParse("00000000-0000-0000-0000-000000000c12"),
		engagementHooli:   uuid.MustParse("00000000-0000-0000-0000-000000000e11"),
		engagementInitech: uuid.MustParse("00000000-0000-0000-0000-000000000e10"),
	}
}

func seedExtraTenants(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	// Three tenants across plans + regions so dashboards / billing /
	// residency surfaces have variety.
	tenants := []struct {
		id       uuid.UUID
		slug     string
		name     string
		region   string
		isolation string
	}{
		{ids.tenantInitech, "initech", "Initech",        "eu",   "shared"},
		{ids.tenantHooli,   "hooli",   "Hooli",          "us",   "dedicated"},
		{ids.tenantRandD,   "raviga",  "Raviga Capital", "apac", "shared"},
	}
	for _, t := range tenants {
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenants(id, platform_id, partner_id, name, slug, status, isolation_mode, data_region)
			VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
			ON CONFLICT (platform_id, slug) DO UPDATE
			   SET data_region = EXCLUDED.data_region,
			       isolation_mode = EXCLUDED.isolation_mode`,
			t.id, ids.platformID, ids.msspID, t.name, t.slug, t.isolation, t.region); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_settings(tenant_id) VALUES ($1)
			ON CONFLICT (tenant_id) DO NOTHING`, t.id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO partner_customer_mapping(partner_id, tenant_id)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`, ids.msspID, t.id); err != nil {
			return err
		}
		// Residency history row so the audit trail isn't empty.
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_residency_history(tenant_id, from_region, to_region, changed_by, reason)
			VALUES ($1, NULL, $2, NULL, 'initial-seed')
			ON CONFLICT DO NOTHING`, t.id, t.region); err != nil {
			return err
		}
	}

	// Engagement for Initech + Hooli so they have a path to scans.
	for _, e := range []struct {
		id       uuid.UUID
		tenant   uuid.UUID
		code     string
		name     string
		intensity string
	}{
		{ids.engagementInitech, ids.tenantInitech, "ENG-INITECH-001", "Initech Quarterly VA", "standard"},
		{ids.engagementHooli,   ids.tenantHooli,   "ENG-HOOLI-001",   "Hooli Continuous PT",  "deep"},
	} {
		now := time.Now().UTC()
		if _, err := tx.Exec(ctx, `
			INSERT INTO engagements(id, platform_id, partner_id, tenant_id,
			    code, name, status, starts_at, ends_at, intensity,
			    emergency_contact_name, emergency_contact_email, emergency_contact_phone)
			VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9,
			    'IT Director', 'security@'||$5||'.example', '+1-555-0199')
			ON CONFLICT (tenant_id, code) DO NOTHING`,
			e.id, ids.platformID, ids.msspID, e.tenant, e.code, e.name,
			now.Add(-7*24*time.Hour), now.Add(83*24*time.Hour), e.intensity); err != nil {
			return err
		}
	}
	return nil
}

// seedUsers persists the demo identities to the users table so the
// /api/v1/auth/dev-token endpoint (dev-only) can mint JWTs that
// resolve to real DB rows. main.go only logged the identities to
// stdout — this puts them where the API can find them.
//
// No password_hash is stored: the platform delegates auth to an
// IdP (Keycloak in dev). The dev-token endpoint bypasses the IdP
// for local development convenience.
func seedUsers(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	users := []struct {
		id        uuid.UUID
		email     string
		fullName  string
		partnerID uuid.UUID
		tenantID  *uuid.UUID
		roles     []string
		mfa       bool
	}{
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000111"),
			email: "admin@zaishield.com", fullName: "ZAISHIELD Super Admin",
			partnerID: uuid.MustParse("00000000-0000-0000-0000-0000000000b1"), // ZAISHIELD direct
			roles: []string{"zaishield_super_admin"}, mfa: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000112"),
			email: "dist@acme-distribution.com", fullName: "ACME Distribution Admin",
			partnerID: ids.distID, roles: []string{"distributor_admin"}, mfa: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000113"),
			email: "manager@acme-mssp.com", fullName: "ACME MSSP Manager",
			partnerID: ids.msspID, roles: []string{"mssp_manager"}, mfa: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000114"),
			email: "pentester@acme-mssp.com", fullName: "ACME Pentester",
			partnerID: ids.msspID, roles: []string{"pentester"}, mfa: false,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000115"),
			email: "viewer@globex.example", fullName: "Globex Read-Only Viewer",
			partnerID: ids.msspID, tenantID: &ids.tenantID,
			roles: []string{"client_viewer"}, mfa: false,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000116"),
			email: "admin@globex.example", fullName: "Globex Tenant Admin",
			partnerID: ids.msspID, tenantID: &ids.tenantID,
			roles: []string{"client_admin"}, mfa: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000117"),
			email: "auditor@external-auditor.example", fullName: "External Auditor",
			partnerID: ids.msspID, tenantID: &ids.tenantID,
			roles: []string{"auditor"}, mfa: true,
		},
	}
	for _, u := range users {
		if _, err := tx.Exec(ctx, `
			INSERT INTO users(id, platform_id, partner_id, tenant_id,
			    email, full_name, mfa_enabled, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
			ON CONFLICT (id) DO NOTHING`,
			u.id, ids.platformID, u.partnerID, u.tenantID,
			u.email, u.fullName, u.mfa); err != nil {
			return err
		}
		// Wire role grants. user_roles has scope_partner +
		// scope_tenant columns; populate the right one based on
		// the user's binding.
		for _, role := range u.roles {
			if _, err := tx.Exec(ctx, `
				INSERT INTO user_roles(user_id, role_id, scope_partner, scope_tenant)
				SELECT $1, id, $2, $3 FROM roles WHERE code = $4
				ON CONFLICT DO NOTHING`,
				u.id, u.partnerID, u.tenantID, role); err != nil {
				return err
			}
		}
	}
	return nil
}

func seedIntegrations(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	now := time.Now().UTC()
	integrations := []struct {
		id        uuid.UUID
		tenantID  uuid.UUID
		intType   string
		name      string
		configJSON string
		enabled   bool
	}{
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000301"),
			tenantID: ids.tenantID, intType: "slack",
			name: "Globex Security Channel",
			configJSON: `{"url":"https://hooks.slack.com/services/T00/B00/EXAMPLE","min_severity":"high"}`,
			enabled: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000302"),
			tenantID: ids.tenantID, intType: "jira",
			name: "Globex Jira SEC project",
			configJSON: `{"api_url":"https://globex.atlassian.net","project":"SEC","issue_type":"Task"}`,
			enabled: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000303"),
			tenantID: ids.tenantID, intType: "siem",
			name: "Globex Splunk CEF",
			configJSON: `{"host":"splunk.globex.example","port":514,"protocol":"tcp","format":"cef"}`,
			enabled: true,
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000304"),
			tenantID: ids.tenantHooli, intType: "webhook",
			name: "Hooli Custom Webhook",
			configJSON: `{"url":"https://hooli.example/vaultscan/in"}`,
			enabled: true,
		},
	}
	for _, i := range integrations {
		if _, err := tx.Exec(ctx, `
			INSERT INTO integrations(id, platform_id, partner_id, tenant_id, type, name,
			    config, enabled, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $9)
			ON CONFLICT (id) DO NOTHING`,
			i.id, ids.platformID, ids.msspID, i.tenantID, i.intType, i.name,
			i.configJSON, i.enabled, now); err != nil {
			return err
		}
	}
	return nil
}

func seedScanJobs(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	now := time.Now().UTC()
	// Three jobs: one completed (with findings already in main.go),
	// one running, one queued for tomorrow. Gives dashboard SSE +
	// retesting + scheduling surfaces real data to render.
	jobs := []struct {
		id       uuid.UUID
		status   string
		profile  string
		started  *time.Time
		finished *time.Time
		scheduled time.Time
	}{
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000401"),
			status: "completed", profile: "external_standard_va",
			started: ptr(now.Add(-2 * time.Hour)), finished: ptr(now.Add(-90 * time.Minute)),
			scheduled: now.Add(-2 * time.Hour),
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000402"),
			status: "running", profile: "internal_discovery",
			started: ptr(now.Add(-15 * time.Minute)),
			scheduled: now.Add(-15 * time.Minute),
		},
		{
			id: uuid.MustParse("00000000-0000-0000-0000-000000000403"),
			status: "queued", profile: "external_deep_pt",
			scheduled: now.Add(24 * time.Hour),
		},
	}
	for _, j := range jobs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_jobs(id, platform_id, partner_id, tenant_id, engagement_id,
			    profile, status, scheduled_at, started_at, finished_at,
			    intensity, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'standard', $8)
			ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status`,
			j.id, ids.platformID, ids.msspID, ids.tenantID, ids.engagementID,
			j.profile, j.status, j.scheduled, j.started, j.finished); err != nil {
			return err
		}
	}
	return nil
}

func seedComplianceEvidence(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	// Pick a representative control from each pre-seeded framework
	// and record an automated 'pass' evidence row so the framework
	// rollup shows green/amber/red instead of all empty.
	now := time.Now().UTC()
	controls := []struct {
		framework, version, code, status, note string
	}{
		{"soc2", "2017", "CC6.1", "pass",
			"Access controls enforced via per-tenant RBAC; verified by integration test"},
		{"soc2", "2017", "CC7.2", "pass",
			"Continuous monitoring via cron-runner audit.VerifyDeep + Prometheus alerts"},
		{"iso27001", "2022", "A.5.10", "manual",
			"Acceptable use enforced via engagement scope + authorization document; auditor review pending"},
		{"iso27001", "2022", "A.8.24", "pass",
			"Per-tenant DEK encryption + KEK rotation cron task; verified by evidence_integrity_sample"},
		{"pci_dss", "4.0", "10.5.1", "pass",
			"Audit log SHA-256 hash chain + RFC 3161 TSA daily anchor"},
		{"gdpr", "2016/679", "Art-17", "pass",
			"users.Erase endpoint pseudonymises across users + login_events + token_revocations"},
		{"gdpr", "2016/679", "Art-32", "pass",
			"Encryption at rest (AES-256-GCM per-tenant DEK); TLS 1.2+ in transit"},
		{"hipaa", "2003", "164.312-a1", "manual",
			"Access controls via RBAC; per-customer BAA on file (auditor verifies)"},
	}
	for _, c := range controls {
		if _, err := tx.Exec(ctx, `
			INSERT INTO compliance_evidence(id, tenant_id, control_id, status,
			    observation_note, evaluated_at)
			SELECT gen_random_uuid(), $1, cc.id, $5, $6, $7
			  FROM compliance_controls cc
			 WHERE cc.framework = $2
			   AND cc.framework_version = $3
			   AND cc.control_code = $4
			ON CONFLICT DO NOTHING`,
			ids.tenantID, c.framework, c.version, c.code,
			c.status, c.note, now); err != nil {
			return err
		}
	}
	return nil
}

func seedAuditLogs(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	// Backfill recent audit-log rows so the audit-export endpoint
	// returns real data instead of nothing for the first week.
	now := time.Now().UTC()
	events := []struct {
		event    string
		actor    uuid.UUID
		target   string
		payload  string
		ago      time.Duration
	}{
		{"tenant.created", uuid.MustParse("00000000-0000-0000-0000-000000000111"),
			ids.tenantID.String(),
			`{"slug":"globex","plan":"business"}`, 30 * 24 * time.Hour},
		{"engagement.activated", uuid.MustParse("00000000-0000-0000-0000-000000000113"),
			ids.engagementID.String(),
			`{"code":"ENG-DEMO-001"}`, 24 * time.Hour},
		{"scan.dispatched", uuid.MustParse("00000000-0000-0000-0000-000000000114"),
			"00000000-0000-0000-0000-000000000401",
			`{"profile":"external_standard_va","tools":["nmap","nuclei","sslyze"]}`,
			2 * time.Hour},
		{"finding.created", uuid.Nil, "",
			`{"count":9,"severities":{"critical":2,"high":3,"medium":2,"low":2}}`,
			90 * time.Minute},
		{"user.login", uuid.MustParse("00000000-0000-0000-0000-000000000116"),
			"00000000-0000-0000-0000-000000000116",
			`{"ip":"203.0.113.50","ua":"Mozilla/5.0"}`, 1 * time.Hour},
		{"integration.delivered", uuid.Nil,
			"00000000-0000-0000-0000-000000000301",
			`{"integration_type":"slack","event":"finding.created","status":"200"}`,
			85 * time.Minute},
		{"tenant.residency_set", uuid.MustParse("00000000-0000-0000-0000-000000000111"),
			ids.tenantInitech.String(),
			`{"from":null,"to":"eu","reason":"MSA §4.2"}`, 12 * time.Hour},
	}
	for _, e := range events {
		var actor *uuid.UUID
		if e.actor != uuid.Nil {
			actor = &e.actor
		}
		var target *string
		if e.target != "" {
			target = &e.target
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_logs(event, actor_id, target_id, payload,
			    tenant_id, occurred_at)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6)
			ON CONFLICT DO NOTHING`,
			e.event, actor, target, e.payload, ids.tenantID,
			now.Add(-e.ago)); err != nil {
			return err
		}
	}
	return nil
}

func seedNotifications(ctx context.Context, tx pgx.Tx, ids seedIDs) error {
	// Notification preferences for the Globex tenant admin so the
	// in-app /api/v1/notifications endpoint returns a non-empty
	// preferences map.
	adminID := uuid.MustParse("00000000-0000-0000-0000-000000000116")
	prefs := []struct {
		channel, event, mode string
	}{
		{"email", "finding.created",       "immediate"},
		{"email", "scan.completed",        "digest_daily"},
		{"slack", "finding.created",       "immediate"},
		{"in_app", "user.invited",         "immediate"},
		{"email", "compliance.failed",     "immediate"},
		{"email", "agent.disconnected",    "immediate"},
	}
	for _, p := range prefs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO notification_preferences(user_id, tenant_id, channel, event_type, mode)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT DO NOTHING`,
			adminID, ids.tenantID, p.channel, p.event, p.mode); err != nil {
			return err
		}
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

// hashSeedSecret is a stable salt used elsewhere to fingerprint
// known demo credentials so they can be excluded from production
// security reports (i.e. "yes we know these creds are weak").
func hashSeedSecret(s string) string {
	h := sha256.Sum256([]byte("vs-seed-" + s))
	return hex.EncodeToString(h[:])
}
