-- §34 Partner integration marketplace. Catalog of available
-- integrations (Slack, Jira, PagerDuty, etc.) + per-tenant installs
-- that wire them to a tenant's notification channels / integration
-- rows.
--
-- Different from integrations (the existing outbound table): a
-- marketplace_listing is a CATALOGUED, vetted integration template;
-- a marketplace_install records the per-tenant choice + config
-- mapping, and on activation creates a row in integrations.

CREATE TABLE marketplace_listings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,           -- 'slack-incident-feed'
    name            TEXT NOT NULL,                  -- 'Slack — Incident Feed'
    publisher       TEXT NOT NULL,                  -- 'ZAISHIELD' | partner name
    category        TEXT NOT NULL,                  -- chat | ticketing | siem | devops | identity
    description     TEXT NOT NULL,
    integration_type TEXT NOT NULL,                 -- slack | jira | servicenow | ...
    config_schema   JSONB NOT NULL DEFAULT '{}',    -- JSONSchema describing required config
    docs_url        TEXT,
    logo_url        TEXT,
    verified        BOOLEAN NOT NULL DEFAULT false, -- ZAISHIELD-signed verification
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX marketplace_listings_category_idx
    ON marketplace_listings(category, enabled);

-- Seed the most-requested integrations so a fresh install has a
-- non-empty catalog. Real deployments add more via the admin UI.
INSERT INTO marketplace_listings(slug, name, publisher, category, description,
    integration_type, config_schema, docs_url, verified) VALUES
  ('slack-incident-feed', 'Slack — Incident Feed', 'ZAISHIELD', 'chat',
   'Posts critical finding alerts + scan completion summaries to a Slack channel.',
   'slack',
   '{"type":"object","required":["url"],"properties":{"url":{"type":"string","format":"uri","title":"Incoming webhook URL"}}}',
   'https://docs.zaishield.com/integrations/slack', true),

  ('jira-vulnerability-tickets', 'Jira — Vulnerability Tickets', 'ZAISHIELD', 'ticketing',
   'Opens a Jira issue for every critical/high finding with CVE + CVSS as custom fields.',
   'jira',
   '{"type":"object","required":["api_url","project_key","issue_type"],"properties":{"api_url":{"type":"string"},"project_key":{"type":"string"},"issue_type":{"type":"string","enum":["Bug","Task","Vulnerability"]}}}',
   'https://docs.zaishield.com/integrations/jira', true),

  ('pagerduty-critical-alerts', 'PagerDuty — Critical Alerts', 'ZAISHIELD', 'incident',
   'Triggers a PagerDuty incident for every critical finding.',
   'pagerduty',
   '{"type":"object","required":["routing_key"],"properties":{"routing_key":{"type":"string"}}}',
   'https://docs.zaishield.com/integrations/pagerduty', true),

  ('servicenow-incident-link', 'ServiceNow — Incident Link', 'ZAISHIELD', 'ticketing',
   'Opens a ServiceNow incident; severity mapped from finding severity.',
   'servicenow',
   '{"type":"object","required":["api_url","caller_id"],"properties":{"api_url":{"type":"string"},"caller_id":{"type":"string"}}}',
   'https://docs.zaishield.com/integrations/servicenow', true),

  ('siem-cef-forwarder', 'SIEM — CEF Event Forwarder', 'ZAISHIELD', 'siem',
   'Forwards normalized findings to any SIEM accepting CEF over syslog or HTTPS.',
   'siem',
   '{"type":"object","required":["url","format"],"properties":{"url":{"type":"string"},"format":{"type":"string","enum":["cef","leef","json"]}}}',
   'https://docs.zaishield.com/integrations/siem', true),

  ('github-issue-sync', 'GitHub — Issue Sync', 'ZAISHIELD', 'devops',
   'Mirrors high/critical findings to a GitHub repo''s issue tracker.',
   'github',
   '{"type":"object","required":["repo","token_ref"],"properties":{"repo":{"type":"string"},"token_ref":{"type":"string","description":"secret reference"}}}',
   'https://docs.zaishield.com/integrations/github', true),

  ('gitlab-issue-sync', 'GitLab — Issue Sync', 'ZAISHIELD', 'devops',
   'Same as GitHub but for GitLab projects.',
   'gitlab',
   '{"type":"object","required":["project","token_ref"]}',
   'https://docs.zaishield.com/integrations/gitlab', true),

  ('teams-incident-feed', 'Microsoft Teams — Incident Feed', 'ZAISHIELD', 'chat',
   'Same as Slack incident feed but for Microsoft Teams channels.',
   'teams',
   '{"type":"object","required":["webhook"],"properties":{"webhook":{"type":"string","format":"uri"}}}',
   'https://docs.zaishield.com/integrations/teams', true);

-- Per-tenant marketplace installs. install_state transitions:
-- pending_config → active → suspended.
CREATE TABLE marketplace_installs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id      UUID NOT NULL REFERENCES marketplace_listings(id),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_id  UUID REFERENCES integrations(id) ON DELETE SET NULL,
    install_state   TEXT NOT NULL DEFAULT 'pending_config',
    installed_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    suspended_at    TIMESTAMPTZ,
    suspension_reason TEXT,
    UNIQUE (tenant_id, listing_id)
);
CREATE INDEX marketplace_installs_tenant_idx
    ON marketplace_installs(tenant_id, install_state);
