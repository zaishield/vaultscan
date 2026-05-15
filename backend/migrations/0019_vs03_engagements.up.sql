-- VS-03 deepening: per-engagement rate limit, intensity cap enforcement,
-- pause/resume bookkeeping, authorization-doc access audit.

-- pause_reason + pause_at + paused_by feed the engagement timeline.
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS pause_reason TEXT;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS paused_at    TIMESTAMPTZ;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS paused_by    UUID
    REFERENCES users(id) ON DELETE SET NULL;

-- Per-engagement scan ceiling (overrides the tenant default when set).
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS max_scans_per_hour INTEGER;

-- Each authorization-document view writes one row here. Lets the auditor
-- prove who saw the signed approval letter and when. Independent of the
-- evidence_access_logs path because auth docs are tracked separately in
-- audit / compliance reporting.
CREATE TABLE authorization_access_logs (
    id           BIGSERIAL PRIMARY KEY,
    document_id  UUID NOT NULL REFERENCES authorization_documents(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    action       TEXT NOT NULL,   -- view | download
    ip           INET,
    user_agent   TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_access_doc_idx ON authorization_access_logs(document_id, occurred_at DESC);

-- Intensity ladder. Used by Scope Guard to refuse a job whose profile
-- intensity exceeds the engagement's max_intensity.
-- Values: light(1) < standard(2) < aggressive(3).
-- (Stored as TEXT in scan_profiles + engagements; the comparison ladder
-- lives in code so adding a new tier doesn't require a schema migration.)
