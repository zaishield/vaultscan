-- HS-01 deepening: actually enable Row Level Security on the tables
-- whose policies migration 0017 defined.
--
-- Without ALTER TABLE ... ENABLE ROW LEVEL SECURITY, the policies are
-- inert. We additionally FORCE row level security so the table-owner
-- role (the vaultscan app user) is bound by the policies — without
-- FORCE, the owner bypasses RLS by default and the policies would be
-- cosmetic.
--
-- Service paths that need cross-tenant reads (analytics worker, cosign
-- verifier) skip the GUC; the policy's NULL branch lets those queries
-- through unfiltered. HTTP middleware that handles authenticated
-- portal traffic calls db.SetTenantContext on every request so the
-- filter binds the user's view to their tenant.
--
-- Defense-in-depth: even with this in place, the application still
-- adds tenant_id WHERE clauses everywhere. RLS catches anything the
-- application forgot.

ALTER TABLE findings         ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets           ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings         FORCE ROW LEVEL SECURITY;
ALTER TABLE assets           FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence FORCE ROW LEVEL SECURITY;

-- Make set_tenant available as a tiny SQL function so application code
-- doesn't have to remember the SET-statement form. NULL or empty tenant
-- → reset the variable (policy becomes pass-through).
CREATE OR REPLACE FUNCTION vaultscan_set_tenant_id(t uuid) RETURNS void AS $$
  SELECT set_config('vaultscan.tenant_id',
                    COALESCE(t::text, ''),
                    false);  -- false = session-scoped, not LOCAL
$$ LANGUAGE sql VOLATILE;
