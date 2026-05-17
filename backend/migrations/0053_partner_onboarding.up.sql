-- 0053_partner_onboarding.up.sql
--
-- Tracks where each partner is in their first-day onboarding so the
-- portal can show "you have 3 of 6 setup steps left" instead of
-- silently letting them ship with the placeholder #0F172A / #38BDF8
-- palette every new partner gets at Create time.
--
-- The model is intentionally simple: one row per partner, one
-- boolean per onboarding milestone, with `completed_at` timestamps
-- for audit. Once all milestones flip to true the row is "complete"
-- and the portal stops nagging.

CREATE TABLE IF NOT EXISTS partner_onboarding (
    partner_id              UUID PRIMARY KEY REFERENCES partners(id) ON DELETE CASCADE,
    -- Per-step booleans. Each toggles independently; the portal can
    -- complete them out of order.
    branding_set            BOOLEAN NOT NULL DEFAULT false,
    branding_set_at         TIMESTAMPTZ,
    logo_uploaded           BOOLEAN NOT NULL DEFAULT false,
    logo_uploaded_at        TIMESTAMPTZ,
    domain_registered       BOOLEAN NOT NULL DEFAULT false,
    domain_registered_at    TIMESTAMPTZ,
    support_configured      BOOLEAN NOT NULL DEFAULT false,
    support_configured_at   TIMESTAMPTZ,
    sender_dns_verified     BOOLEAN NOT NULL DEFAULT false,
    sender_dns_verified_at  TIMESTAMPTZ,
    first_tenant_created    BOOLEAN NOT NULL DEFAULT false,
    first_tenant_created_at TIMESTAMPTZ,
    -- Computed at SELECT time; a denormalised completed_at saves the
    -- portal a CASE expression on every dashboard render.
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed onboarding rows for every existing partner so the portal can
-- show progress for partners created before this migration.
INSERT INTO partner_onboarding(partner_id)
SELECT id FROM partners
ON CONFLICT (partner_id) DO NOTHING;
