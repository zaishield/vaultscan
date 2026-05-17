-- VS-01 Platform Foundation & Authentication
-- Blueprint §9, §20.1, §20.2, §23

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ===========================================================================
-- Platform / Partner / Tenant hierarchy (Blueprint §8.2, §9, §20.2)
-- ===========================================================================

CREATE TABLE platforms (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        CITEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE partner_types (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,    -- distributor | reseller | mssp | white_label | direct
    description TEXT NOT NULL
);

INSERT INTO partner_types(code, description) VALUES
    ('distributor',  'Manages multiple resellers in a region'),
    ('reseller',     'Sells and supports customers'),
    ('mssp',         'Operates scans and remediation workflows'),
    ('white_label',  'Fully rebrands the product'),
    ('direct',       'Direct customer of ZAISHIELD')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE partners (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    parent_id       UUID REFERENCES partners(id) ON DELETE SET NULL,
    type_id         UUID NOT NULL REFERENCES partner_types(id),
    name            TEXT NOT NULL,
    slug            CITEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform_id, slug)
);
CREATE INDEX partners_parent_idx ON partners(parent_id);

CREATE TABLE partner_reseller_mapping (
    distributor_id UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    reseller_id    UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    PRIMARY KEY (distributor_id, reseller_id)
);

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id     UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    partner_id      UUID NOT NULL REFERENCES partners(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL,
    slug            CITEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    isolation_mode  TEXT NOT NULL DEFAULT 'shared',  -- shared | dedicated
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform_id, slug)
);
CREATE INDEX tenants_partner_idx ON tenants(partner_id);

CREATE TABLE partner_customer_mapping (
    partner_id UUID NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,
    PRIMARY KEY (partner_id, tenant_id)
);

CREATE TABLE tenant_settings (
    tenant_id            UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    timezone             TEXT NOT NULL DEFAULT 'UTC',
    default_severity_sla JSONB NOT NULL DEFAULT '{"critical": 7, "high": 14, "medium": 30, "low": 90}',
    allow_aggressive     BOOLEAN NOT NULL DEFAULT false,
    blackout_windows     JSONB NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tenant branding (white-label override level)
CREATE TABLE tenant_branding (
    tenant_id     UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    product_name  TEXT,
    logo_url      TEXT,
    favicon_url   TEXT,
    primary_color TEXT,
    secondary_color TEXT,
    legal_footer  TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===========================================================================
-- Users / Roles / Permissions (Blueprint §23)
-- ===========================================================================

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id   UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    partner_id    UUID REFERENCES partners(id) ON DELETE SET NULL,
    tenant_id     UUID REFERENCES tenants(id)  ON DELETE SET NULL,
    email         CITEXT NOT NULL,
    full_name     TEXT NOT NULL,
    keycloak_sub  TEXT,
    mfa_enabled   BOOLEAN NOT NULL DEFAULT false,
    status        TEXT NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform_id, email)
);
CREATE INDEX users_tenant_idx  ON users(tenant_id);
CREATE INDEX users_partner_idx ON users(partner_id);

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    scope_level TEXT NOT NULL    -- platform | partner | tenant | engagement
);

INSERT INTO roles(code, name, scope_level) VALUES
    ('zaishield_super_admin',   'ZAISHIELD Super Admin',     'platform'),
    ('platform_security_admin', 'Platform Security Admin',   'platform'),
    ('distributor_admin',       'Distributor Admin',         'partner'),
    ('reseller_admin',          'Reseller Admin',            'partner'),
    ('mssp_manager',            'MSSP Manager',              'partner'),
    ('mssp_analyst',            'MSSP Analyst',              'engagement'),
    ('tenant_admin',            'Tenant Admin',              'tenant'),
    ('engagement_manager',      'Engagement Manager',        'engagement'),
    ('pentester',               'Pentester',                 'engagement'),
    ('analyst',                 'Analyst',                   'engagement'),
    ('remediation_owner',       'Remediation Owner',         'engagement'),
    ('client_viewer',           'Client Viewer',             'tenant'),
    ('auditor',                 'Auditor',                   'platform'),
    ('agent_installer',         'Agent Installer',           'tenant')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE permissions (
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

INSERT INTO permissions(code, description) VALUES
    ('create_partner',          'Create partner records'),
    ('manage_branding',         'Edit branding for a partner or tenant'),
    ('create_tenant',           'Create tenant records'),
    ('create_engagement',       'Create new engagements'),
    ('approve_scope',           'Approve scope targets for an engagement'),
    ('upload_authorization',    'Upload signed authorization documents'),
    ('create_scan_job',         'Create scan jobs'),
    ('approve_aggressive_scan', 'Approve aggressive / intrusive scans'),
    ('view_findings',           'Read findings in scope'),
    ('edit_findings',           'Triage / status / comment on findings'),
    ('request_retest',          'Request a retest of a finding'),
    ('execute_retest',          'Execute a retest scan'),
    ('generate_report',         'Generate a report'),
    ('download_evidence',       'Download evidence artifacts'),
    ('manage_agents',           'Enroll, configure, and remove agents'),
    ('trigger_emergency_stop',  'Trigger emergency stop on agents or scans'),
    ('view_audit_logs',         'Read audit logs')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- user_roles uses a synthetic surrogate key + a unique partial expression
-- index. PRIMARY KEY itself can't contain expressions, but UNIQUE INDEX can.
CREATE TABLE user_roles (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id        UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_partner  UUID REFERENCES partners(id) ON DELETE CASCADE,
    scope_tenant   UUID REFERENCES tenants(id)  ON DELETE CASCADE,
    granted_by     UUID REFERENCES users(id),
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX user_roles_unique_idx
    ON user_roles (
        user_id, role_id,
        COALESCE(scope_partner, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(scope_tenant,  '00000000-0000-0000-0000-000000000000'::uuid)
    );
CREATE INDEX user_roles_user_idx ON user_roles(user_id);
CREATE INDEX user_roles_role_idx ON user_roles(role_id);
