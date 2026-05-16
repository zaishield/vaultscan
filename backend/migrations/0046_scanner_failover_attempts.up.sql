-- 0046 — Cross-region scanner failover audit trail.
--
-- Closes the SEV-3 multi-region failover gap: NodeOps tracked region
-- quotas + degraded-node failover within a region, but
-- pickScannerNode was single-leader-per-region. With this commit
-- pickScannerNode walks a configured failover ladder
-- (VAULTSCAN_REGION_FAILOVER) when the primary has no eligible
-- node. Each cross-region pick writes one row here so ops can
-- alert on chronic primary unavailability.

BEGIN;

CREATE TABLE IF NOT EXISTS scanner_failover_attempts (
    id           BIGSERIAL PRIMARY KEY,
    from_region  TEXT NOT NULL,
    to_region    TEXT NOT NULL,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scanner_failover_attempts_recent_idx
    ON scanner_failover_attempts(decided_at DESC);
CREATE INDEX IF NOT EXISTS scanner_failover_attempts_pair_idx
    ON scanner_failover_attempts(from_region, to_region, decided_at DESC);

COMMIT;
