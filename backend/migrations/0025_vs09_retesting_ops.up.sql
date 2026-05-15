-- VS-09 deepening: auto-retest on remediation, bulk retest batches,
-- diff between original finding state and the retest's findings.

-- Tenant preference: when a finding flips to 'remediated', the system
-- automatically files a retest request. Default off so it doesn't fire
-- for tenants that haven't reviewed the policy.
ALTER TABLE tenant_settings ADD COLUMN IF NOT EXISTS auto_retest_on_remediated BOOLEAN
    NOT NULL DEFAULT false;

-- Per-finding rollup: latest retest outcome + when. Lets the findings
-- list render a "Retest: passed 3 days ago" badge without joining
-- retest_results.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_retest_outcome TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_retest_at      TIMESTAMPTZ;

-- Bulk retest queue. An operator selecting 50 findings produces one
-- batch + 50 retest_requests. The batch tracks progress in aggregate.
CREATE TABLE retest_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(id),
    reason          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',  -- open | in_progress | completed | cancelled
    total_items     INTEGER NOT NULL,
    completed_items INTEGER NOT NULL DEFAULT 0,
    failed_items    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX retest_batches_tenant_idx ON retest_batches(tenant_id, status);

CREATE TABLE retest_batch_items (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id          UUID NOT NULL REFERENCES retest_batches(id) ON DELETE CASCADE,
    retest_request_id UUID NOT NULL REFERENCES retest_requests(id) ON DELETE CASCADE,
    ordinal           INTEGER NOT NULL,
    state             TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | failed
    UNIQUE (batch_id, retest_request_id)
);
CREATE INDEX retest_batch_items_batch_idx
    ON retest_batch_items(batch_id, state);

-- Diff between the original finding snapshot at retest_request time and
-- the post-retest state. Lets the UI show "severity dropped from high to
-- medium" or "still present, no change".
CREATE TABLE retest_diffs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    retest_request_id UUID NOT NULL REFERENCES retest_requests(id) ON DELETE CASCADE,
    original_snapshot JSONB NOT NULL,         -- captured at request time
    post_snapshot     JSONB,                  -- captured at result time
    diff              JSONB NOT NULL DEFAULT '{}',
    summary           TEXT,
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (retest_request_id)
);
