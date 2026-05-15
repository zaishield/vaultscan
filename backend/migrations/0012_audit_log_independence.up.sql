-- Audit/log tables must record every attempt — including attempts that
-- reference non-existent or wrong-tenant entities. Foreign keys on these
-- tables silently drop those rows. Replace the FKs with plain UUID columns
-- so Scope Guard / scan approval / audit logging always succeed.

ALTER TABLE scope_decision_logs DROP CONSTRAINT IF EXISTS scope_decision_logs_engagement_id_fkey;
ALTER TABLE scope_decision_logs DROP CONSTRAINT IF EXISTS scope_decision_logs_tenant_id_fkey;
ALTER TABLE scope_decision_logs DROP CONSTRAINT IF EXISTS scope_decision_logs_requested_by_fkey;

ALTER TABLE scan_approval_logs DROP CONSTRAINT IF EXISTS scan_approval_logs_job_fk;
ALTER TABLE scan_approval_logs DROP CONSTRAINT IF EXISTS scan_approval_logs_approved_by_fkey;

ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_partner_id_fkey;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_tenant_id_fkey;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_id_fkey;

-- The hash chain must be byte-stable across Record() and Verify(). Postgres
-- JSONB canonicalises the payload on storage ('{"a":1}' becomes
-- '{"a": 1}' on read-back), so re-hashing the JSONB bytes on Verify diverges
-- from what Record hashed and silently fails. Switch to TEXT so the byte
-- sequence round-trips exactly. JSON path operators ('payload->>') are not
-- used anywhere in the codebase; callers unmarshal payload as opaque JSON
-- on read, which still works against TEXT.
ALTER TABLE audit_logs ALTER COLUMN payload TYPE TEXT USING payload::text;
