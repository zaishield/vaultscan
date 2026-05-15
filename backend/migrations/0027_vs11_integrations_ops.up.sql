-- VS-11 deepening: typed Jira issues, ServiceNow incidents, CEF/LEEF
-- SIEM output, dead-letter queue for failed deliveries.

CREATE TABLE integration_dead_letters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    event_id        UUID NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    attempts        INTEGER NOT NULL,
    last_error      TEXT,
    last_status_code INTEGER,
    enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    resolution      TEXT             -- replayed | dropped | quarantined
);
CREATE INDEX integration_dead_letters_pending_idx
    ON integration_dead_letters(integration_id, enqueued_at)
    WHERE resolved_at IS NULL;

CREATE TABLE integration_replays (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dead_letter_id  UUID NOT NULL REFERENCES integration_dead_letters(id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(id),
    outcome         TEXT NOT NULL DEFAULT 'pending', -- pending | delivered | failed
    status_code     INTEGER,
    response_body   TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- New per-integration knobs.
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS format     TEXT;   -- json | cef | leef
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS issue_type TEXT;   -- Jira: Bug | Task | Vulnerability
