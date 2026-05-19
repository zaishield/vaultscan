# SOC 2 / ISO 27001 evidence collection workflow

The platform produces a signed quarterly evidence bundle via the
`cmd/audit-bundle` binary. This runbook explains the process from
collection to handoff to an external auditor.

## The bundle in one minute

`cmd/audit-bundle` reads the production database, assembles a
tar.gz containing:

- `verify_deep.json` — full audit-chain integrity report
- `chain_breaks.json` — every detected break (empty == healthy)
- `verification_checkpoints.json` — proves the cron actually ran
- `tenant_data_keys_inventory.json` — DEK metadata only (no key material)
- `retention_policies.json` — what the sweeper enforces
- `manifest.json` — SHA-256 of every artifact above + summary
- `bundle.sig` — HMAC-SHA256 over `manifest.json` (optional)

The bundle contains NO tenant payloads, NO user PII, NO key
material. It IS safe to share with an external auditor.

## Quarterly collection procedure

### Step 1: Generate the bundle

Run from a privileged operator host (NOT a public CronJob — the
DB credentials must not appear in any pod with traffic-handler
exposure):

```bash
HMAC_KEY=$(openssl rand -hex 32)
echo "$HMAC_KEY" > /secure/vault/q1-2026-bundle-signing.key

./audit-bundle \
  -db $VAULTSCAN_DATABASE_URL \
  -sign-key "$HMAC_KEY" \
  -output /tmp/vaultscan-soc2-2026-Q1.tar.gz
```

The HMAC key is the ONLY material the auditor needs to verify
authenticity. Store it separately from the bundle (separate
KMS path, separate physical media if you're being thorough).

### Step 2: Archive locally + offsite

```bash
# Local archive
mv /tmp/vaultscan-soc2-2026-Q1.tar.gz \
   /var/lib/vaultscan/compliance-archive/

# Offsite — your encrypted S3 bucket or equivalent
aws s3 cp /var/lib/vaultscan/compliance-archive/vaultscan-soc2-2026-Q1.tar.gz \
  s3://your-compliance-vault/vaultscan/2026/Q1/ \
  --server-side-encryption aws:kms \
  --sse-kms-key-id $YOUR_COMPLIANCE_KMS_KEY
```

Retention: 7 years for SOC 2 Type II evidence (verify against
your specific contractual retention obligations).

### Step 3: Hand off to auditor

Provide:
- The bundle tar.gz
- The HMAC signing key (via a separate, signed channel — encrypted
  email, signed phone call, etc.)
- A pointer to this document

The auditor verifies:

```bash
# They run this against the bundle you sent them.
audit-bundle verify vaultscan-soc2-2026-Q1.tar.gz \
  -sign-key <the hex key you sent separately>
```

Successful output:
```
audit-bundle verify: OK (6 artifacts, generated_at=2026-04-01T00:00:00Z)
```

Any tamper produces a clear FAIL with specific artifact + computed
vs expected SHA-256.

## What auditors care about (and where to point them)

| Auditor question | Bundle artifact | Interpretation |
|---|---|---|
| "Is the audit chain intact?" | `verify_deep.json` | `first_bad_id` MUST be `0`. Anything else is a chain break. |
| "Did you actually run the integrity check?" | `verification_checkpoints.json` | `last_verified_at` should be within the cron interval (hourly in our deployment). `rows_verified_total` is monotonic. |
| "Have you detected ANY tampering?" | `chain_breaks.json` | An empty array `[]` is the desired state. Any entries warrant root-cause analysis. |
| "Show me the key rotation cadence" | `tenant_data_keys_inventory.json` | Group by `kek_id` + `created_at`. Operators rotate every 90/180/365 days per the secret-rotation runbook. |
| "What's your data retention policy?" | `retention_policies.json` | Per-event-type retention in days. Auditor compares to your published policy. |

## Failure modes

### chain_breaks.json is not empty

A break means SOMETHING modified an audit row without going
through the proper chain-aware path. Investigate immediately:

1. Check `git log` for any recent migration that touched
   `audit_logs`
2. Pull the most recent `VerifyDeep` output from logs (the
   `bundle` only captures the latest run)
3. Cross-reference the break's row range with operator activity
   in the same window

A break is NOT auto-recoverable. Procedure is in
`docs/runbooks/audit-chain-break-response.md` (separate runbook).

### bundle.sig verification fails

If `audit-bundle verify -sign-key X` reports SIGNATURE MISMATCH:

1. Confirm the key you handed the auditor is the same one
   used to produce the bundle. Most common cause: typo on
   transcription.
2. Confirm `manifest.json` wasn't modified after signing. The
   bundle is designed to be opaque after creation; if you've
   edited it, regenerate from scratch.
3. If neither, this is suspected tampering. Treat as a security
   incident.

### A specific artifact sha256 doesn't match the manifest

Treat as suspected tampering. Pull the original from the offsite
archive and compare.

## Automation

For deployments that prefer automated collection, a Kubernetes
CronJob spec might look like:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vaultscan-audit-bundle-quarterly
spec:
  schedule: "0 0 1 1,4,7,10 *"  # Q1, Q2, Q3, Q4 starts
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: bundler
            image: vaultscan/audit-bundle:latest
            env:
              - name: VAULTSCAN_DATABASE_URL
                valueFrom: { secretKeyRef: { name: vs-db, key: url } }
              - name: BUNDLE_SIGN_KEY
                valueFrom: { secretKeyRef: { name: vs-compliance, key: bundle-key } }
            command:
              - /bin/sh
              - -c
              - |
                TS=$(date -u +%Y-Q%q)
                /audit-bundle \
                  -db $VAULTSCAN_DATABASE_URL \
                  -sign-key $BUNDLE_SIGN_KEY \
                  -output /out/vs-soc2-$TS.tar.gz
                aws s3 cp /out/vs-soc2-$TS.tar.gz \
                  s3://your-compliance-vault/vaultscan/$TS/ \
                  --server-side-encryption aws:kms
            volumeMounts:
              - name: out
                mountPath: /out
          volumes:
            - name: out
              emptyDir: {}
```

(NOT included in this repo's manifests — `cmd/audit-bundle` is
the binary; the operator owns the deployment shape.)

## Verification of THIS document

The audit-bundle integration test (`backend/cmd/audit-bundle/main_test.go`)
covers:

- `TestAuditBundle_RealRun` — full generate + read-back, asserts
  every documented artifact is present, manifest sha256s match,
  and bundle.sig HMAC validates.
- `TestAuditBundle_VerifySubcommand`:
  - `good_signature` — verify with correct key succeeds + prints OK
  - `wrong_signature` — verify with wrong key exits non-zero
  - `no_signature_flag` — verify without key skips sig check but
    still validates all sha256s

Run them against the test container:
```bash
cd backend && VAULTSCAN_TEST_DATABASE_URL=... \
  go test -tags=integration -v -run TestAuditBundle ./cmd/audit-bundle/
```
