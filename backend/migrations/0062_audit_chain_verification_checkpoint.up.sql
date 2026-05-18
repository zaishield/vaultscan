-- 0062_audit_chain_verification_checkpoint.up.sql
--
-- VerifyDeep already chunks the audit_logs scan via keyset paging
-- (LIMIT 10000 + WHERE id > $1) so each statement returns fast.
-- The remaining scale gap is restart-resumability: a kill mid-scan
-- on a tenant with tens of millions of audit rows would force the
-- next run to start over from row 1, paying for the same I/O all
-- over again.
--
-- This table persists the (last_verified_id, last_verified_hash)
-- pair after a successful VerifyDeep run. VerifyIncremental reads
-- it on entry, resumes from the next row, and advances the
-- checkpoint on success. A break detected at any row clears the
-- forward edge — operators must run a full VerifyDeep to confirm
-- the entire history is intact before incremental can resume.
--
-- Single-row table by design: there is one audit chain per
-- deployment (audit_logs.platform_id is per-row but the chain
-- itself spans every row in id order). A primary key on (id=1)
-- makes ON CONFLICT trivial.

CREATE TABLE IF NOT EXISTS audit_chain_verification_checkpoints (
    id                  SMALLINT  PRIMARY KEY DEFAULT 1
        CHECK (id = 1),                -- enforce single-row invariant
    last_verified_id    BIGINT    NOT NULL,
    last_verified_hash  BYTEA     NOT NULL,
    last_verified_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rows_verified_total BIGINT    NOT NULL DEFAULT 0
);

-- Seed an empty checkpoint (id=0) so VerifyIncremental can do an
-- UPDATE on every run instead of branching on row-exists.
INSERT INTO audit_chain_verification_checkpoints(id, last_verified_id, last_verified_hash)
VALUES (1, 0, '\x'::bytea)
ON CONFLICT (id) DO NOTHING;
