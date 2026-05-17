-- 0052_billing_quota_enforcement.up.sql
--
-- Extends partner_billing_plans with the bookkeeping fields needed
-- for live quota enforcement, and adds a counter-snapshot table the
-- API can return without re-running the full count queries on every
-- request.
--
-- Convention: quota=0 means UNLIMITED (matches the existing schema
-- defaults so any pre-existing partner_billing_plans row that was
-- never explicitly set still behaves as "no limit"). Switching a
-- partner from no-plan to a tiered plan is a deliberate INSERT.

-- A short label + currency for the plan, plus billing cadence. The
-- platform itself doesn't bill — it just records the metadata so a
-- billing-aware portal or downstream invoice generator can read it.
ALTER TABLE partner_billing_plans
    ADD COLUMN IF NOT EXISTS name           TEXT,
    ADD COLUMN IF NOT EXISTS price_cents    BIGINT,
    ADD COLUMN IF NOT EXISTS currency       TEXT NOT NULL DEFAULT 'USD',
    ADD COLUMN IF NOT EXISTS billing_cycle  TEXT NOT NULL DEFAULT 'monthly',
    ADD COLUMN IF NOT EXISTS overage_policy TEXT NOT NULL DEFAULT 'block',  -- block | warn | allow
    ADD COLUMN IF NOT EXISTS created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at     TIMESTAMPTZ NOT NULL DEFAULT now();

-- "Active plan" lookup happens via valid_from/valid_to. Add an
-- index that the quota service hits on every check.
CREATE INDEX IF NOT EXISTS partner_billing_plans_active_idx
    ON partner_billing_plans(partner_id, valid_from DESC)
    WHERE valid_to IS NULL OR valid_to > now();

-- Per-quota-check audit row. Helps support understand why a customer
-- saw a 429 ("you've hit your scan quota for this billing period").
-- One row per BLOCKED check; allow-through checks aren't logged
-- (would explode the table).
CREATE TABLE IF NOT EXISTS partner_quota_blocks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id       UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    tenant_id        UUID REFERENCES tenants(id) ON DELETE SET NULL,
    plan_id          UUID REFERENCES partner_billing_plans(id) ON DELETE SET NULL,
    quota_kind       TEXT NOT NULL,  -- asset | scan | agent
    current_usage    INTEGER NOT NULL,
    quota_limit      INTEGER NOT NULL,
    actor_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    blocked_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason           TEXT
);
CREATE INDEX IF NOT EXISTS partner_quota_blocks_partner_idx
    ON partner_quota_blocks(partner_id, blocked_at DESC);
CREATE INDEX IF NOT EXISTS partner_quota_blocks_recent_idx
    ON partner_quota_blocks(blocked_at DESC);

-- Convenience view: the current effective plan per partner. Cron jobs
-- + the quota service both read this to avoid replicating the
-- valid_from/valid_to logic.
CREATE OR REPLACE VIEW partner_active_plan AS
SELECT DISTINCT ON (partner_id)
       partner_id,
       id          AS plan_id,
       plan_code,
       name,
       asset_quota,
       scan_quota,
       agent_quota,
       overage_policy,
       currency,
       price_cents,
       billing_cycle,
       valid_from,
       valid_to
  FROM partner_billing_plans
 WHERE valid_from <= now()
   AND (valid_to IS NULL OR valid_to > now())
 ORDER BY partner_id, valid_from DESC;
