-- 0064_sso_state_consumed.up.sql
--
-- Single-use enforcement for SSO state cookies. Closes the replay
-- window where a captured state cookie remained valid until expiry
-- (10 min) and could be replayed by an attacker on a failed callback.
--
-- Mechanism: every state cookie carries a `jti` (JWT ID, a random
-- UUID). On successful callback, we INSERT the jti here. The unique
-- constraint enforces one-time use: a replay attempts the same INSERT
-- and trips ERROR 23505. We treat the constraint violation as
-- ErrStateInvalid → 401, identical to a forged cookie.
--
-- Retention: rows older than 1h are purged by the cron-runner's
-- existing sso_state_consumed_sweep job. State cookies expire at
-- 10 min so 1h gives a comfortable margin.

CREATE TABLE IF NOT EXISTS sso_state_consumed (
    jti          UUID PRIMARY KEY,
    consumed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sso_state_consumed_age_idx
    ON sso_state_consumed (consumed_at);
