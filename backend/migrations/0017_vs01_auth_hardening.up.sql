-- VS-01 deepening: tenant suspension, session revocation list, row-level
-- security guard, login attempt counters.

-- Tenant status already exists (active|suspended); add a reason column and
-- track when it changed so we can show "suspended by X on Y because Z" in
-- the portal.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspension_reason TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspended_at      TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspended_by      UUID
    REFERENCES users(id) ON DELETE SET NULL;

-- Session / token revocation list. JWTs are stateless by design so revocation
-- needs a blocklist of jti values (or 'all tokens issued before T for user U').
-- We use the latter pattern — much cheaper than per-jti — keyed off the
-- user_id with a min_iat timestamp.
CREATE TABLE token_revocations (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    min_iat     TIMESTAMPTZ NOT NULL,   -- any token issued before this is invalid
    revoked_by  UUID REFERENCES users(id),
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason      TEXT
);

-- Login attempt counter for brute-force defence. Reset on every successful
-- login; if the count exceeds the threshold the user is locked until an
-- admin resets it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;

-- Row-level security policies. We don't ENABLE RLS by default because the
-- application enforces tenant isolation at the middleware layer; flipping
-- it on without thoroughly auditing every query path could break things
-- mid-session. Define the policies so an operator can flip RLS on for
-- defense-in-depth without code changes.
CREATE OR REPLACE FUNCTION vaultscan_current_tenant_id() RETURNS uuid AS $$
  SELECT NULLIF(current_setting('vaultscan.tenant_id', true), '')::uuid;
$$ LANGUAGE sql STABLE;

DO $$ BEGIN
  -- Drop any prior policy of the same name so this migration is rerunnable.
  EXECUTE 'DROP POLICY IF EXISTS findings_tenant_isolation ON findings';
  EXECUTE 'DROP POLICY IF EXISTS assets_tenant_isolation   ON assets';
  EXECUTE 'DROP POLICY IF EXISTS evidence_tenant_isolation ON finding_evidence';
EXCEPTION WHEN OTHERS THEN NULL; END $$;

CREATE POLICY findings_tenant_isolation ON findings
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
CREATE POLICY assets_tenant_isolation ON assets
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());
CREATE POLICY evidence_tenant_isolation ON finding_evidence
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());

-- Tenant timezone is read by the dashboard renderer + email scheduler.
ALTER TABLE tenant_settings ADD COLUMN IF NOT EXISTS contact_email TEXT;
ALTER TABLE tenant_settings ADD COLUMN IF NOT EXISTS slack_channel TEXT;
