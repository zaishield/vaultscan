-- 0052_billing_quota_enforcement.down.sql
DROP VIEW IF EXISTS partner_active_plan;
DROP INDEX IF EXISTS partner_quota_blocks_recent_idx;
DROP INDEX IF EXISTS partner_quota_blocks_partner_idx;
DROP TABLE IF EXISTS partner_quota_blocks;
DROP INDEX IF EXISTS partner_billing_plans_active_idx;
ALTER TABLE partner_billing_plans
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS created_at,
    DROP COLUMN IF EXISTS overage_policy,
    DROP COLUMN IF EXISTS billing_cycle,
    DROP COLUMN IF EXISTS currency,
    DROP COLUMN IF EXISTS price_cents,
    DROP COLUMN IF EXISTS name;
