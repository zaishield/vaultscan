# Disaster Recovery Runbook

This runbook is the authoritative recovery procedure for VAULTSCAN. It is
exercised at least quarterly via the `tools/scripts/dr-drill.sh` script
and the result is recorded in `audit_logs` under
`event = ops.dr.drill_completed`.

## RPO / RTO targets

| Component               | RPO   | RTO    | Backup mechanism                              |
|-------------------------|-------|--------|-----------------------------------------------|
| Postgres (control plane)| 5 min | 30 min | Continuous WAL archiving + nightly `pg_dump`  |
| Evidence vault (object) | 0     | 30 min | Per-object replication via Ceph RGW          |
| OpenSearch (analytics)  | 1 hr  | 2 hr   | Snapshot-and-restore plugin to S3            |
| Keycloak realm          | 24 hr | 30 min | Daily realm export to S3                     |
| Secret stores (OpenBao) | 0     | 60 min | Raft replication + sealed-key off-box backup |

## Restore drill — control plane Postgres

Run from a workstation with `kubectl` and `aws` CLI configured.

```bash
# 1. Pick the most recent good backup
LATEST=$(aws s3 ls s3://vaultscan-backups/$(date -u +%Y-%m-%d)/ \
         --endpoint-url ${S3_ENDPOINT} \
         | awk '{print $4}' | tail -1)
echo "Restoring from ${LATEST}"

# 2. Spin a clean Postgres in the DR namespace.
helm upgrade --install vaultscan-dr-pg bitnami/postgresql \
  --namespace vaultscan-dr \
  --set auth.postgresPassword=$(openssl rand -hex 24) \
  --set primary.persistence.size=200Gi

# 3. Stream the dump in.
kubectl exec -n vaultscan-dr vaultscan-dr-pg-0 -- bash -c "\
  aws s3 cp s3://vaultscan-backups/$(date -u +%Y-%m-%d)/${LATEST} - \
  --endpoint-url ${S3_ENDPOINT} \
  | gunzip \
  | pg_restore --no-owner --no-privileges \
      --jobs=4 -d postgres -h localhost -U postgres"

# 4. Run the migrations binary to bring the schema up to current head.
kubectl create job --from=cronjob/vaultscan-migrate dr-migrate -n vaultscan-dr

# 5. Re-enable RLS + reset DEKs (per-tenant DEKs survive; KEK must match).
kubectl exec -n vaultscan-dr vaultscan-dr-pg-0 -- psql -U vaultscan \
  -c "SELECT count(*) FROM tenant_data_keys"

# 6. Verify audit chain integrity.
curl -sf https://api-dr.vaultscan.zaishield.com/api/v1/audit/verify \
  | jq '.first_bad_id'   # MUST be 0
```

## Failover — full region loss

1. Engage the on-call: `ops-oncall@zaishield.com`.
2. Promote the standby region's Postgres to primary:
   ```
   kubectl exec postgres-standby-0 -- /scripts/promote.sh
   ```
3. Update the global DNS `api.vaultscan.zaishield.com` weight to 100%
   on the standby region.
4. Re-issue agent certificates pointing at the standby agent-gateway:
   ```
   ./tools/scripts/agent-cert-rebroadcast.sh --gateway agent-gw-eu-1
   ```
5. Verify scope guard, audit chain, and a synthetic scan end-to-end.
6. Post incident timeline to `#vaultscan-incidents`.

## Evidence vault — bit-rot detection

The retention worker also runs `VerifyIntegrity` on each evidence
object once per quarter. A failure logs a `integrity_failed` row
in `evidence_chain_of_custody` and alerts on
`event=evidence.integrity_failed`.

## Audit chain — break recovery

`audit_chain_breaks` records the first detected divergence. The
operator's playbook:

1. Snapshot the current database (DR backup above).
2. Stop write traffic via maintenance mode (HS-05).
3. Inspect rows around `first_bad_id` for evidence of tampering.
4. Engage the legal team; **do not** truncate or delete the chain.
5. Re-seal the chain by creating a `audit.chain.repaired` event that
   references the gap; downstream forensics can still trace the gap.

## Quarterly drill checklist

- [ ] Restore last 7d of pg backups into the DR namespace
- [ ] Restore one tenant's evidence vault and verify SHA-256 roundtrip
- [ ] Replay 24h of integration_dead_letters
- [ ] Run `VerifyDeep` against the DR audit chain
- [ ] Generate a compliance report for tenant `globex-example`
- [ ] Record drill outcome via `POST /api/v1/audit/drill`
