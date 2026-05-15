-- §24 Mobile portal: thin API for the iOS/Android apps. The mobile
-- surface is intentionally minimal — view dashboards, ack alerts,
-- approve scope changes, view findings, trigger emergency stop.
--
-- Push-notification tokens (APNS / FCM) are mapped to users so the
-- alerting engine can fan critical findings out to subscribed
-- devices.

CREATE TABLE mobile_device_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL,           -- ios | android
    push_token      TEXT NOT NULL,           -- APNS device token / FCM registration id
    app_version     TEXT,
    os_version      TEXT,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    UNIQUE (user_id, push_token)
);
CREATE INDEX mobile_device_tokens_user_idx
    ON mobile_device_tokens(user_id) WHERE revoked_at IS NULL;

-- Mobile-side ack of a critical alert. Lets the SOC see "yes, the
-- on-call saw the page on their phone at 02:14".
CREATE TABLE mobile_alert_acks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    finding_id    UUID REFERENCES findings(id) ON DELETE SET NULL,
    notification_id UUID,
    ack_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id     UUID REFERENCES mobile_device_tokens(id) ON DELETE SET NULL
);
CREATE INDEX mobile_alert_acks_finding_idx
    ON mobile_alert_acks(finding_id) WHERE finding_id IS NOT NULL;
