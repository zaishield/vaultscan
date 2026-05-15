-- HS-05 deepening: maintenance mode, break-glass tokens, policy engine
-- for never-allow / always-require rules from Blueprint §36.

-- Platform-wide maintenance mode. When `enabled=true`, every API write
-- responds with 503 + Retry-After unless the caller has the
-- `maintenance.override` permission. Reads remain available. Toggling
-- writes an audit row, never an environment-variable change.
CREATE TABLE platform_maintenance (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enabled           BOOLEAN NOT NULL DEFAULT false,
    reason            TEXT,
    started_at        TIMESTAMPTZ,
    expected_end_at   TIMESTAMPTZ,
    last_changed_by   UUID REFERENCES users(id),
    last_changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO platform_maintenance(enabled) VALUES (false);

-- Break-glass token. An operator can mint a one-time, short-TTL token
-- that grants a specific permission outside the normal RBAC tree —
-- useful when SSO is broken or an emergency requires an action no
-- existing role permits. Every use is audited; tokens self-destruct
-- on first redemption.
CREATE TABLE break_glass_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id       UUID NOT NULL REFERENCES users(id),
    granted_permission TEXT NOT NULL,
    reason          TEXT NOT NULL,
    token_hash      TEXT NOT NULL,           -- bcrypt(token)
    expires_at      TIMESTAMPTZ NOT NULL,
    redeemed_at     TIMESTAMPTZ,
    redeemed_by     UUID REFERENCES users(id),
    redeemed_ip     INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX break_glass_tokens_unused_idx
    ON break_glass_tokens(expires_at) WHERE redeemed_at IS NULL;

-- Policy rules from Blueprint §36. Each row is one rule of the form
-- "if condition then verdict". The evaluator iterates active rules and
-- the first match wins. Rules are seeded from §36.1/§36.2 + can be
-- extended per partner / per tenant.
CREATE TABLE platform_policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL,
    rule_class      TEXT NOT NULL,            -- never_allow | always_require
    subject         TEXT NOT NULL,            -- scan | finding | report | login | api_call
    condition       JSONB NOT NULL,           -- {"out_of_scope": true} etc.
    verdict         TEXT NOT NULL,            -- deny | require | warn
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX platform_policy_rules_lookup_idx
    ON platform_policy_rules(subject, enabled);

INSERT INTO platform_policy_rules(name, description, rule_class, subject, condition, verdict) VALUES
  ('never_allow_out_of_scope',
   'Block any scan with out_of_scope=true (Blueprint §36.1)',
   'never_allow','scan','{"out_of_scope":true}','deny'),
  ('never_allow_expired_engagement',
   'Block any scan against an expired engagement',
   'never_allow','scan','{"engagement_expired":true}','deny'),
  ('never_allow_anonymous_scan',
   'Block scan creation without an authenticated identity',
   'never_allow','scan','{"actor_id":null}','deny'),
  ('never_allow_plaintext_credentials',
   'Refuse integration config carrying plaintext secrets',
   'never_allow','api_call','{"plaintext_credentials":true}','deny'),

  ('always_require_authorization_document',
   'Engagement must have an active authorization document',
   'always_require','scan','{"requires":"authorization_documents"}','require'),
  ('always_require_signed_manifest',
   'Scan job must carry a verified signature',
   'always_require','scan','{"requires":"signed_manifest"}','require'),
  ('always_require_tenant_context',
   'Every API call must carry a resolved tenant context',
   'always_require','api_call','{"requires":"tenant_id"}','require'),
  ('always_require_mfa_for_privileged',
   'Privileged roles must use MFA',
   'always_require','login','{"requires":"mfa_for_role:platform_admin"}','require');
