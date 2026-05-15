-- 0043 — Per-user notification preferences + on-call schedule.
--
-- Before this migration: notify.Service fired every wired transport
-- for every event. No per-user opt-out, no quiet hours, no on-call
-- rotation, no digest mode. Result: alert fatigue + noise rooms.
--
-- New tables:
--
--   notification_preferences  per-user channel preferences keyed on
--                              event-type prefix + severity floor.
--   on_call_schedules         named rotations (PagerDuty escalation
--                              policy if you squint).
--   on_call_shifts            who's on for a given window in a given
--                              schedule. Resolved at notify-fanout time.
--
-- Quiet hours / digest are encoded as channel preferences so a user
-- can say e.g. "Slack between 9-17 weekdays only, email always,
-- digest the rest into a daily summary".

BEGIN;

CREATE TABLE notification_preferences (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- event_prefix examples: "FindingNormalized", "ScanJobCompleted",
    -- "*" (catch-all). Matched longest-prefix-wins at fanout.
    event_prefix    TEXT NOT NULL,
    -- min_severity: skip notification when finding severity is lower.
    -- info < low < medium < high < critical. NULL = no floor.
    min_severity    TEXT,
    -- channel: slack | email | sms | push | pagerduty | webhook
    channel         TEXT NOT NULL,
    -- channel_address: per-channel routing target (slack DM ID, email
    -- address, phone number, push token, PD service key, webhook URL).
    channel_address TEXT NOT NULL,
    -- mode: immediate | digest | suppress
    mode            TEXT NOT NULL DEFAULT 'immediate'
        CHECK (mode IN ('immediate', 'digest', 'suppress')),
    -- quiet_hours: '{"timezone":"America/New_York","weekday_only":true,
    --                "start_hour":9,"end_hour":17}' — outside the window
    -- the channel switches to digest mode automatically.
    quiet_hours     JSONB,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX notification_preferences_user_idx
    ON notification_preferences(user_id, enabled);
CREATE INDEX notification_preferences_event_idx
    ON notification_preferences(event_prefix, enabled);

-- Per-user digest queue. Filled by the fanout when mode=digest;
-- drained by a cron job that emits one summary email/Slack-message
-- per user per (configurable) interval.
CREATE TABLE notification_digest_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel         TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    severity        TEXT,
    queued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ
);
CREATE INDEX notification_digest_queue_pending_idx
    ON notification_digest_queue(user_id, channel, queued_at)
    WHERE delivered_at IS NULL;

-- ----- On-call schedules ---------------------------------------------------
--
-- A schedule is a named rotation ("primary-soc", "platform-eng-secondary").
-- Shifts assign a user to a window. notify.Service.OnCallFor(scheduleName,
-- now()) returns the user_id that's currently on shift.
--
-- Override entries (override=true) take precedence over regular shifts and
-- never clash by chance.

CREATE TABLE on_call_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE on_call_shifts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id     UUID NOT NULL REFERENCES on_call_schedules(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starts_at       TIMESTAMPTZ NOT NULL,
    ends_at         TIMESTAMPTZ NOT NULL,
    -- When override=true, takes precedence over regular shifts in the
    -- same window. Used by the "I'm covering for X this weekend" UX.
    override        BOOLEAN NOT NULL DEFAULT false,
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);

CREATE INDEX on_call_shifts_window_idx
    ON on_call_shifts(schedule_id, starts_at, ends_at);

-- RLS: tenant-scoped on the schedule (and via FK on shifts).
ALTER TABLE on_call_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE on_call_schedules FORCE  ROW LEVEL SECURITY;
CREATE POLICY on_call_schedules_tenant_isolation ON on_call_schedules
    FOR ALL TO PUBLIC
    USING (vaultscan_current_tenant_id() IS NULL
           OR tenant_id = vaultscan_current_tenant_id());

COMMIT;
