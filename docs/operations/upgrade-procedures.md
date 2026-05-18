# Upgrade procedures

How to safely upgrade a running VaultScan deployment between versions.

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`):

| Bump | Allowed in this version line | Action required |
| --- | --- | --- |
| PATCH (`1.0.0` → `1.0.1`) | bug fixes, security patches; no behaviour change | Rolling helm upgrade |
| MINOR (`1.0.0` → `1.1.0`) | new endpoints, new tables (additive), opt-in features | Rolling helm upgrade + read CHANGELOG |
| MAJOR (`1.x` → `2.0.0`) | removed endpoints, schema changes, env-var renames | Customer migration window; see "Major upgrades" below |

## Pre-upgrade checklist (every upgrade)

```bash
# 1. Confirm the new release exists + the digests are populated.
gh release view vX.Y.Z
jq '.digests | length' tools/scanner-images/digests.json  # > 0

# 2. Read the CHANGELOG section for this version. STOP if you see
#    "BREAKING:" notices you haven't planned for.
awk -v v="X.Y.Z" '$0 ~ "^## \\["v"\\]"{f=1;next} f && /^## \[/{exit} f' CHANGELOG.md

# 3. Verify the current cluster is healthy (no in-flight incidents).
kubectl get pods -n vaultscan
curl -s "$API/readyz" | grep -q ok

# 4. Take a fresh DB backup OUTSIDE the regular cron (so it doesn't
#    rotate before the upgrade is verified).
make backup-snapshot   # or cloud-native equivalent

# 5. Capture pre-upgrade metric baseline so you can compare after.
curl -s "$PROMETHEUS_URL/api/v1/query?query=vaultscan_request_total" \
  > /tmp/pre-upgrade-baseline.json
```

## Patch upgrade (`1.0.0` → `1.0.1`)

```bash
# 1. Pull the new chart version.
helm pull oci://registry.zaishield.com/vaultscan/charts/vaultscan --version 1.0.1
# 2. Diff (chart drift only; values should be unchanged).
helm diff upgrade vaultscan ./vaultscan-1.0.1 -n vaultscan \
  -f values-prod.yaml
# 3. Apply.
helm upgrade vaultscan ./vaultscan-1.0.1 -n vaultscan \
  -f values-prod.yaml
# 4. Watch the roll.
kubectl rollout status -n vaultscan deployment/vaultscan-api
kubectl rollout status -n vaultscan deployment/vaultscan-agent-gateway
# 5. Smoke-test.
curl -s "$API/api/v1/status" | jq .version
# expect: "1.0.1"
```

Patch upgrades have ZERO downtime (rolling update, max-surge 1,
max-unavailable 0).

## Minor upgrade (`1.0.x` → `1.1.0`)

Same as patch PLUS:

```bash
# 1. Migrations: the chart includes a Job that runs migrate -up
#    before the new Deployment rolls. Watch the Job.
kubectl logs -n vaultscan job/vaultscan-migrate -f
# 2. Review the new endpoints / cron tasks listed in the CHANGELOG
#    Added section.
# 3. Update Helm values if the release notes flag new opt-in flags
#    (e.g. networkPolicies.externalEgress.cidrBlocks).
# 4. Verify cron-runner picked up new tasks:
kubectl logs -n vaultscan -l app=vaultscan-cron-runner \
  --tail=50 | grep "cron-runner started"
# Expected line: "jobs": N where N matches the count in main.go.
```

## Major upgrade (`1.x` → `2.0.0`)

Major upgrades have BREAKING changes. Don't roll blind.

### 4 weeks before

- Read the migration guide for `2.0.0` (published with the release).
- Identify every breaking change that affects your deployment.
- Identify integration partners that need API changes (your SOC,
  ticketing, SIEM).
- Schedule a customer-facing maintenance window (1-2 hours).

### 1 week before

- Stand up a clone of production against the `v2.0.0` chart.
- Re-run your full integration test suite.
- Re-run the k6 capacity test (`capacity-validation-runbook.md`).

### Upgrade day

```bash
# 1. Enter maintenance mode (returns 503 with Retry-After + status page).
curl -X POST "$API/api/v1/platform/maintenance" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"enabled":true,"message":"Upgrading to v2.0.0; ~1h"}'

# 2. Snapshot the DB.
make backup-snapshot

# 3. Run the upgrade.
helm upgrade vaultscan ./vaultscan-2.0.0 -n vaultscan \
  -f values-prod.yaml

# 4. Verify migrations ran cleanly.
kubectl logs -n vaultscan job/vaultscan-migrate
# Look for the version number in the last line:
# > applied migrations: ...

# 5. Smoke-test every customer-impacting flow:
#    - login + MFA
#    - submit a scan
#    - dashboard load
#    - report generation
#    - integration delivery (use a test webhook target)

# 6. Exit maintenance mode.
curl -X POST "$API/api/v1/platform/maintenance" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"enabled":false}'

# 7. Watch metrics for 60 min before declaring success.
```

## Rollback

### Patch / minor

```bash
helm rollback vaultscan <previous-revision> -n vaultscan
```

Migrations are forward-only in the chart's Job; the rollback restores
the previous chart values but does NOT down-migrate by default. If
the new minor added a NOT NULL column you need to either:
- run the down migration manually (`kubectl exec ... -- migrate -down 1`)
- OR keep the new column (it's harmless) and just roll back the app

### Major rollback (last resort)

```bash
# 1. Restore the DB from snapshot.
make restore-snapshot SNAPSHOT_ID=<id>
# 2. Roll back the chart.
helm rollback vaultscan <previous-revision> -n vaultscan
# 3. Exit maintenance.
```

Total RTO: 30-60 min depending on DB size.

## Failure during upgrade

| Symptom | Action |
| --- | --- |
| Migrate Job fails | Tail logs; inspect the migration SQL; if recoverable, manually fix + re-run; if not, roll back chart + restore DB snapshot |
| New Deployment pods CrashLoopBackOff | Look at logs; usually a new required env var missing — set it + re-apply |
| API serving 5xx after roll | Roll back chart (DB schema typically stays — additive migrations are safe) |
| Kyverno blocks the new image | See `kyverno-policy-violations.md` |

## Audit

Every upgrade lands a `platform.upgrade` event in `audit_logs` with
the old + new chart versions + the operator who ran it. Reviewable
via:

```bash
curl -s "$API/api/v1/audit/export?event=platform.upgrade" \
  -H "Authorization: Bearer $ADMIN_JWT" | jq
```

## Related

- `release-runbook.md` (publishing the release that's being upgraded to)
- `disaster-recovery.md` (when an upgrade goes catastrophically wrong)
- `incident-response.md` (if customers report issues post-upgrade)
