// seed populates the local stack with a demo distributor, MSSP, customer
// tenant, engagement, scope, agent stub, assets, and a handful of findings
// across severities. Idempotent: re-runs are safe.
//
// Production never invokes this binary. The Docker image ships it for use by
// the make seed target only.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/logging"
)

func main() {
	dropFlag := flag.Bool("drop", false, "remove demo records before re-seeding (lossy)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed: config:", err)
		os.Exit(2)
	}
	log := logging.New(cfg.Env)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer pool.Close()

	// Demo IDs are deterministic so reruns are stable across teardowns.
	// The ZAISHIELD direct partner (b1) is already seeded by migration 0010;
	// we only add a distributor + MSSP + customer tenant below.
	platformID := uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	distID := uuid.MustParse("00000000-0000-0000-0000-0000000000d1")
	msspID := uuid.MustParse("00000000-0000-0000-0000-0000000000d2")
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000c01")
	clientID := uuid.MustParse("00000000-0000-0000-0000-000000000c02")
	engagementID := uuid.MustParse("00000000-0000-0000-0000-000000000e01")
	agentID := uuid.MustParse("00000000-0000-0000-0000-000000000a01")

	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("begin tx")
	}
	defer tx.Rollback(ctx)

	if *dropFlag {
		// Cascade everything tied to the demo tenant.
		for _, q := range []string{
			"DELETE FROM tenants WHERE id=$1",
			"DELETE FROM partners WHERE id=ANY($2::uuid[])",
		} {
			if _, err := tx.Exec(ctx, q, tenantID, []uuid.UUID{distID, msspID}); err != nil {
				log.Warn().Err(err).Str("query", q).Msg("drop")
			}
		}
	}

	// Distributor + MSSP under ZAISHIELD.
	if _, err := tx.Exec(ctx, `
		INSERT INTO partners(id, platform_id, parent_id, type_id, name, slug, status)
		SELECT $1, $2, NULL, pt.id, 'ACME Distribution EMEA', 'acme-distribution', 'active'
		  FROM partner_types pt WHERE pt.code='distributor'
		ON CONFLICT (platform_id, slug) DO NOTHING`,
		distID, platformID); err != nil {
		log.Fatal().Err(err).Msg("insert distributor")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO partners(id, platform_id, parent_id, type_id, name, slug, status)
		SELECT $1, $2, $3, pt.id, 'ACME Managed Security', 'acme-mssp', 'active'
		  FROM partner_types pt WHERE pt.code='mssp'
		ON CONFLICT (platform_id, slug) DO NOTHING`,
		msspID, platformID, distID); err != nil {
		log.Fatal().Err(err).Msg("insert mssp")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO partner_reseller_mapping(distributor_id, reseller_id)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`, distID, msspID); err != nil {
		log.Fatal().Err(err).Msg("link distributor->mssp")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO partner_branding(partner_id, product_name, primary_color, secondary_color,
		    legal_footer, support_email, sender_email, sender_name,
		    watermark_text, confidentiality_tag)
		VALUES
		($1, 'ACME Cyber Distribution', '#FF6B00', '#FF8C00',
		 'ACME Distribution EMEA. All rights reserved.',
		 'support@acme-distribution.com', 'no-reply@acme-distribution.com',
		 'ACME Distribution', 'CONFIDENTIAL', 'CONFIDENTIAL'),
		($2, 'ACME Managed Security', '#FF6B00', '#FF8C00',
		 'ACME Managed Security. All rights reserved.',
		 'support@acme-mssp.com', 'no-reply@acme-mssp.com',
		 'ACME MSSP', 'CONFIDENTIAL', 'CONFIDENTIAL')
		ON CONFLICT (partner_id) DO NOTHING`, distID, msspID); err != nil {
		log.Fatal().Err(err).Msg("insert partner branding")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO partner_support_settings(partner_id) VALUES ($1), ($2)
		ON CONFLICT (partner_id) DO NOTHING`, distID, msspID); err != nil {
		log.Fatal().Err(err).Msg("partner support settings")
	}

	// Customer tenant under the MSSP.
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenants(id, platform_id, partner_id, name, slug, status, isolation_mode)
		VALUES ($1, $2, $3, 'Globex Corp', 'globex', 'active', 'shared')
		ON CONFLICT (platform_id, slug) DO NOTHING`,
		tenantID, platformID, msspID); err != nil {
		log.Fatal().Err(err).Msg("insert tenant")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_settings(tenant_id) VALUES ($1)
		ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		log.Fatal().Err(err).Msg("tenant settings")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO partner_customer_mapping(partner_id, tenant_id)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`, msspID, tenantID); err != nil {
		log.Fatal().Err(err).Msg("link partner->tenant")
	}

	// Engagement + authorization document + approved scope.
	if _, err := tx.Exec(ctx, `
		INSERT INTO clients(id, tenant_id, name, industry, contact_name, contact_email)
		VALUES ($1, $2, 'Globex Corp', 'manufacturing', 'Hank Scorpio', 'hank@globex.example')
		ON CONFLICT (id) DO NOTHING`, clientID, tenantID); err != nil {
		log.Fatal().Err(err).Msg("insert client")
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO engagements(id, platform_id, partner_id, tenant_id, client_id,
		    code, name, description, status, starts_at, ends_at, intensity,
		    emergency_contact_name, emergency_contact_email, emergency_contact_phone)
		VALUES ($1, $2, $3, $4, $5,
		    'ENG-DEMO-001', 'Globex Annual VA/PT',
		    'Quarterly external + internal assessment for Globex Corp',
		    'active', $6, $7, 'standard',
		    'Hank Scorpio', 'hank@globex.example', '+1-555-0100')
		ON CONFLICT (tenant_id, code) DO NOTHING`,
		engagementID, platformID, msspID, tenantID, clientID,
		now.Add(-24*time.Hour), now.Add(30*24*time.Hour)); err != nil {
		log.Fatal().Err(err).Msg("insert engagement")
	}

	// Authorization document - a stub blob, hash recorded for §14.5 / §24.2.
	authBody := []byte("AUTHORIZATION LETTER (DEMO)\nClient: Globex Corp\nScope: globex.example, 10.0.0.0/16\n")
	authSum := sha256.Sum256(authBody)
	if _, err := tx.Exec(ctx, `
		INSERT INTO authorization_documents(id, engagement_id, title, document_type,
		    storage_url, sha256, signed_by, encrypted)
		VALUES (gen_random_uuid(), $1, 'Globex Annual VA Authorization', 'letter',
		    'vaultscan://demo/auth-doc', $2, 'Hank Scorpio', true)
		ON CONFLICT DO NOTHING`,
		engagementID, hex.EncodeToString(authSum[:])); err != nil {
		log.Fatal().Err(err).Msg("insert auth doc")
	}

	// Approved scope targets.
	scopes := []struct {
		typ, val, plane string
	}{
		{"domain", "globex.example", "external"},
		{"cidr", "10.0.0.0/16", "internal"},
	}
	for _, s := range scopes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scope_targets(engagement_id, target_type, target_value, plane,
			    status, approved_at)
			VALUES ($1, $2, $3, $4, 'approved', now())
			ON CONFLICT (engagement_id, target_type, target_value) DO NOTHING`,
			engagementID, s.typ, s.val, s.plane); err != nil {
			log.Fatal().Err(err).Msg("insert scope")
		}
	}

	// Assets covering 6 of the 14 supported types.
	assets := []struct {
		typ, value, plane, crit string
	}{
		{"domain", "globex.example", "external", "high"},
		{"subdomain", "api.globex.example", "external", "high"},
		{"ip", "203.0.113.42", "external", "medium"},
		{"webapp", "https://portal.globex.example", "external", "critical"},
		{"server", "ad-01.corp.globex.local", "internal", "critical"},
		{"database", "db-01.corp.globex.local", "internal", "high"},
	}
	for _, a := range assets {
		if _, err := tx.Exec(ctx, `
			INSERT INTO assets(platform_id, partner_id, tenant_id, engagement_id,
			    asset_type, name, value, plane, criticality, discovered_via)
			VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, 'manual')
			ON CONFLICT (tenant_id, asset_type, value) DO UPDATE SET last_seen=now()`,
			platformID, msspID, tenantID, engagementID, a.typ, a.value, a.plane, a.crit); err != nil {
			log.Fatal().Err(err).Msg("insert asset")
		}
	}

	// Pending demo agent (no certificate yet — provision via the portal to enroll).
	if _, err := tx.Exec(ctx, `
		INSERT INTO agents(id, platform_id, partner_id, tenant_id, name, location,
		    form_factor, status, cert_status, emergency_stop_armed)
		VALUES ($1, $2, $3, $4, 'globex-dc01', 'Globex HQ data center',
		    'linux_vm', 'pending', 'none', true)
		ON CONFLICT (tenant_id, name) DO NOTHING`,
		agentID, platformID, msspID, tenantID); err != nil {
		log.Fatal().Err(err).Msg("insert agent")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_policies(agent_id, allowed_scopes, blocked_scopes,
		    allowed_scan_profiles, allowed_tools)
		VALUES ($1,
		    '["10.0.0.0/16","corp.globex.local"]'::jsonb,
		    '["10.0.99.0/24"]'::jsonb,
		    '["internal_discovery","internal_standard_va","internal_ad_review"]'::jsonb,
		    '["nmap","openvas","nuclei","bloodhound","netexec","lynis"]'::jsonb)
		ON CONFLICT (agent_id) DO NOTHING`, agentID); err != nil {
		log.Fatal().Err(err).Msg("insert agent policy")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_assigned_scope(agent_id, engagement_id)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`, agentID, engagementID); err != nil {
		log.Fatal().Err(err).Msg("assign agent scope")
	}

	// Sample findings across severities so dashboards have data.
	findings := []struct {
		title, sev, scanner, scanType, endpoint, cve string
		cvss                                          float64
	}{
		{"Exposed Tomcat manager on 8080", "critical", "nmap", "network",
			"203.0.113.42:8080", "CVE-2017-12615", 9.8},
		{"TLS 1.0 still enabled", "high", "testssl", "tls",
			"https://portal.globex.example", "", 7.5},
		{"X-Frame-Options header missing", "medium", "zap", "web",
			"https://portal.globex.example", "", 5.4},
		{"Outdated OpenSSH 7.4", "high", "openvas", "vulnerability",
			"203.0.113.42:22", "CVE-2018-15473", 5.3},
		{"Weak Kerberos pre-auth allowed", "high", "bloodhound", "ad",
			"corp.globex.local", "", 7.2},
		{"Trivy: critical CVE in container base", "critical", "trivy", "container",
			"docker.io/globex/web:1.2", "CVE-2023-44487", 9.1},
		{"AWS S3 bucket world-readable", "medium", "prowler", "cloud",
			"arn:aws:s3:::globex-public-uploads", "", 6.5},
		{"SMB signing not required", "medium", "netexec", "smb",
			"ad-01.corp.globex.local", "", 5.9},
		{"Server returns version banner", "low", "nmap", "network",
			"203.0.113.42:80", "", 3.1},
	}
	for _, f := range findings {
		fp := dedupFP(tenantID, f.title, f.scanner, f.endpoint, f.cve, f.sev)
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings(id, platform_id, partner_id, tenant_id, engagement_id,
			    title, severity, confidence, cvss_score, cve, scanner, scan_type,
			    affected_endpoint, status, first_seen, last_seen, dedup_fingerprint)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'high', $7, $8, $9, $10, $11,
			    'open', now(), now(), $12)
			ON CONFLICT (tenant_id, dedup_fingerprint) DO UPDATE SET last_seen=now()`,
			platformID, msspID, tenantID, engagementID,
			f.title, f.sev, f.cvss, f.cve, f.scanner, f.scanType, f.endpoint, fp); err != nil {
			log.Fatal().Err(err).Msg("insert finding")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		log.Fatal().Err(err).Msg("commit")
	}

	log.Info().
		Str("tenant_id", tenantID.String()).
		Str("partner_id", msspID.String()).
		Str("engagement_id", engagementID.String()).
		Str("agent_id", agentID.String()).
		Int("findings", len(findings)).
		Int("assets", len(assets)).
		Msg("seed complete")

	fmt.Println()
	fmt.Println("Demo identities for the dev-token login page:")
	fmt.Println()
	for _, ident := range []struct{ email, roles string }{
		{"admin@zaishield.com", "zaishield_super_admin"},
		{"dist@acme-distribution.com", "distributor_admin"},
		{"manager@acme-mssp.com", "mssp_manager"},
		{"pentester@acme-mssp.com", "pentester"},
		{"client@globex.example", "client_viewer"},
	} {
		fmt.Printf("  %-30s  roles: %s\n", ident.email, ident.roles)
	}
	fmt.Println()
	fmt.Printf("  partner_id = %s\n", msspID)
	fmt.Printf("  tenant_id  = %s\n", tenantID)
	fmt.Println()
}

func dedupFP(tenant uuid.UUID, title, scanner, endpoint, cve, sev string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		tenant, strings.ToLower(title), scanner,
		strings.ToLower(endpoint), cve, strings.ToLower(sev))
	return hex.EncodeToString(h.Sum(nil))
}
