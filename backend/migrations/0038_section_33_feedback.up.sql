-- §33 Customer feedback loop. In-portal "send feedback" form, NPS
-- prompts, and per-feature thumbs-up/down — fed into a single
-- prioritised backlog the product team works from.

CREATE TABLE customer_feedback (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    category      TEXT NOT NULL,                   -- nps | bug | feature | thumbs_up | thumbs_down | other
    severity      TEXT NOT NULL DEFAULT 'normal',  -- urgent | high | normal | low
    rating        INTEGER,                         -- NPS 0..10; null for other categories
    title         TEXT NOT NULL,
    body          TEXT NOT NULL,
    feature       TEXT,                            -- /findings, /scans/external, etc.
    portal_url    TEXT,                            -- where in the app they triggered the form
    user_agent    TEXT,
    status        TEXT NOT NULL DEFAULT 'new',     -- new | triaged | in_progress | resolved | dismissed
    triaged_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution    TEXT,                            -- short note added on close
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ
);
CREATE INDEX customer_feedback_open_idx
    ON customer_feedback(status, created_at DESC)
    WHERE status IN ('new', 'triaged', 'in_progress');
CREATE INDEX customer_feedback_tenant_idx
    ON customer_feedback(tenant_id, created_at DESC);

-- One row per outbound "how are we doing?" prompt. Lets the product
-- team see "we asked 240 users, 140 answered, NPS = 47".
CREATE TABLE customer_feedback_prompts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,            -- nps | feature_satisfaction | bug_followup
    feature         TEXT,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at    TIMESTAMPTZ,
    feedback_id     UUID REFERENCES customer_feedback(id) ON DELETE SET NULL,
    dismissed_at    TIMESTAMPTZ
);
CREATE INDEX customer_feedback_prompts_user_idx
    ON customer_feedback_prompts(user_id, sent_at DESC);
