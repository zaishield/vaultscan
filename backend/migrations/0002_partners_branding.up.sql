-- VS-02 Partner & White-Label Engine
-- Blueprint §8.4, §20.2

CREATE TABLE partner_branding (
    partner_id        UUID PRIMARY KEY REFERENCES partners(id) ON DELETE CASCADE,
    product_name      TEXT NOT NULL,
    logo_url          TEXT,
    favicon_url       TEXT,
    primary_color     TEXT NOT NULL DEFAULT '#0F172A',
    secondary_color   TEXT NOT NULL DEFAULT '#38BDF8',
    accent_color      TEXT,
    legal_footer      TEXT,
    terms_of_service  TEXT,
    privacy_policy    TEXT,
    support_email     TEXT,
    support_phone     TEXT,
    sender_email      TEXT,
    sender_name       TEXT,
    pdf_cover_url     TEXT,
    watermark_text    TEXT,
    confidentiality_tag TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by        UUID REFERENCES users(id)
);

CREATE TABLE partner_domains (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id     UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    domain         CITEXT NOT NULL UNIQUE,
    is_primary     BOOLEAN NOT NULL DEFAULT false,
    tls_cert_ref   TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX partner_domains_partner_idx ON partner_domains(partner_id);

CREATE TABLE partner_email_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id   UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    code         TEXT NOT NULL,           -- welcome | scan_complete | finding_assigned | report_ready ...
    subject      TEXT NOT NULL,
    body_html    TEXT NOT NULL,
    body_text    TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (partner_id, code)
);

CREATE TABLE partner_report_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id   UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    report_type  TEXT NOT NULL,            -- executive | technical | external_attack | ...
    template     TEXT NOT NULL,            -- jinja2 / handlebars body
    sections     JSONB NOT NULL DEFAULT '[]',
    cover_url    TEXT,
    footer       TEXT,
    watermark    TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (partner_id, report_type)
);

CREATE TABLE partner_billing_plans (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id    UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    plan_code     TEXT NOT NULL,
    asset_quota   INTEGER NOT NULL DEFAULT 0,
    scan_quota    INTEGER NOT NULL DEFAULT 0,
    agent_quota   INTEGER NOT NULL DEFAULT 0,
    valid_from    TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to      TIMESTAMPTZ,
    UNIQUE (partner_id, plan_code, valid_from)
);

CREATE TABLE partner_feature_flags (
    partner_id   UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    flag         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT false,
    payload      JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (partner_id, flag)
);

CREATE TABLE partner_support_settings (
    partner_id     UUID PRIMARY KEY REFERENCES partners(id) ON DELETE CASCADE,
    support_url    TEXT,
    support_email  TEXT,
    support_phone  TEXT,
    sla_response_minutes INTEGER NOT NULL DEFAULT 60,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
