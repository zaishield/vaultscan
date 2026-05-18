-- 0057_rls_gaps_close.up.sql
--
-- Close three RLS coverage gaps surfaced by the GA audit:
--
--   compliance_evidence       (0049)  — tenant-scoped attestation evidence
--   dashboard_sse_subscriptions (0028) — per-tenant SSE topic subs
--   idempotency_keys          (0047)  — per-tenant request dedup
--
-- All three have a tenant_id column but were never enrolled into the
-- baseline RLS policy that migration 0040 applied to the rest of the
-- tenant-scoped tables. Without RLS, a SQL injection or a service-
-- role bypass would cross tenant boundaries on these tables.
--
-- The policy uses the same vaultscan.tenant_id GUC that
-- middleware.TenantBinding sets per request; no application-code
-- change needed.

-- compliance_evidence: already enrolled in RLS by 0045; the
-- guarded block keeps the migration idempotent.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
     WHERE schemaname = current_schema()
       AND tablename = 'compliance_evidence'
       AND policyname = 'compliance_evidence_tenant_isolation'
  ) THEN
    ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;
    ALTER TABLE compliance_evidence FORCE ROW LEVEL SECURITY;
    CREATE POLICY compliance_evidence_tenant_isolation
      ON compliance_evidence
      USING (
        tenant_id::text = current_setting('vaultscan.tenant_id', true)
        OR current_setting('vaultscan.tenant_id', true) = ''
        OR current_setting('vaultscan.tenant_id', true) IS NULL
      );
  END IF;
END $$;

-- dashboard_sse_subscriptions --------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
     WHERE schemaname = current_schema()
       AND tablename = 'dashboard_sse_subscriptions'
       AND policyname = 'dashboard_sse_subscriptions_tenant_isolation'
  ) THEN
    ALTER TABLE dashboard_sse_subscriptions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE dashboard_sse_subscriptions FORCE ROW LEVEL SECURITY;
    CREATE POLICY dashboard_sse_subscriptions_tenant_isolation
      ON dashboard_sse_subscriptions
      USING (
        tenant_id::text = current_setting('vaultscan.tenant_id', true)
        OR current_setting('vaultscan.tenant_id', true) = ''
        OR current_setting('vaultscan.tenant_id', true) IS NULL
      );
  END IF;
END $$;

-- idempotency_keys -------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
     WHERE schemaname = current_schema()
       AND tablename = 'idempotency_keys'
       AND policyname = 'idempotency_keys_tenant_isolation'
  ) THEN
    ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
    ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
    CREATE POLICY idempotency_keys_tenant_isolation
      ON idempotency_keys
      USING (
        tenant_id::text = current_setting('vaultscan.tenant_id', true)
        OR current_setting('vaultscan.tenant_id', true) = ''
        OR current_setting('vaultscan.tenant_id', true) IS NULL
      );
  END IF;
END $$;

-- audit_logs --------------------------------------------------------
-- The original 0040 sweep deliberately excluded audit_logs on the
-- assumption that platform admin tooling reads the table without a
-- tenant GUC. That assumption is preserved here: the policy's
-- NULL-tenant escape (current_setting IS NULL OR '') lets platform
-- callers pass through unfiltered. But the moment a tenant-scoped
-- session DOES set the GUC (every request that goes through
-- middleware.TenantBinding), RLS pins the read to that tenant.
-- That closes the SOC2-grade cross-tenant-leak hole that
-- TestRLS_TenantCannotReadOtherTenant_AuditLogs surfaced.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
     WHERE schemaname = current_schema()
       AND tablename = 'audit_logs'
       AND policyname = 'audit_logs_tenant_isolation'
  ) THEN
    ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
    CREATE POLICY audit_logs_tenant_isolation
      ON audit_logs
      USING (
        tenant_id IS NULL
        OR tenant_id::text = current_setting('vaultscan.tenant_id', true)
        OR current_setting('vaultscan.tenant_id', true) = ''
        OR current_setting('vaultscan.tenant_id', true) IS NULL
      );
  END IF;
END $$;

-- Performance + correctness extras ---------------------------------

-- Composite indices for the hot dashboard / SLA queries. The
-- portal lists "findings open in tenant X past 30d" + "scan jobs
-- by status in tenant Y" + "audit events of type Z in tenant W
-- since cutoff" on every page load. Today those queries scan
-- the tenant_id index then re-filter — costly at scale.
CREATE INDEX IF NOT EXISTS findings_tenant_status_created_idx
  ON findings (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS scan_jobs_tenant_status_created_idx
  ON scan_jobs (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_tenant_event_occurred_idx
  ON audit_logs (tenant_id, event, occurred_at DESC);

-- Audit-chain tail lookup. verify-deep currently full-scans to
-- find the head; with this partial index it's an index-only seek.
CREATE INDEX IF NOT EXISTS audit_logs_chain_tail_idx
  ON audit_logs (id DESC)
  WHERE chain_hash IS NOT NULL;

-- CHECK constraints on the documented enum-like columns. Refuses
-- silent insertion of invalid values that would only be caught
-- much later when a dashboard tries to filter by them. Guarded so
-- re-running this migration is a no-op.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'findings_severity_check') THEN
    ALTER TABLE findings
      ADD CONSTRAINT findings_severity_check
      CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'findings_status_check') THEN
    ALTER TABLE findings
      ADD CONSTRAINT findings_status_check
      CHECK (status IN (
        'open', 'triaged', 'assigned', 'in_progress',
        'risk_accepted', 'false_positive', 'remediated',
        'retest_requested', 'retest_passed', 'retest_failed', 'closed'
      ));
  END IF;
END $$;
