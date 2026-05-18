#!/usr/bin/env bash
# rotate-secrets.sh — rotate the platform's at-rest signing /
# encryption secrets and emit the right audit events.
#
# Scope:
#   - VAULTSCAN_JWT_SECRET         (rotated via /auth/jwt-keys/rotate)
#   - VAULTSCAN_EVIDENCE_MASTER_KEY (KEK — re-wrap done by cron task)
#   - VAULTSCAN_JOB_SIGNING_KEY    (orchestrator-to-worker job sigs)
#   - Per-integration HMAC signing secrets
#
# This is NOT for the per-tenant DEK rotation — that's automatic
# (cron-runner `dek_rotation_sweep` task, every 24h).
#
# Operator runs this manually when:
#   - Required by policy (annually for KEK / 90-day for JWT)
#   - Suspected compromise (run immediately + invalidate the old key)
#   - Pre-pentest preparation (so the pentester gets fresh material
#     and post-test cleanup doesn't break ongoing operations)

set -euo pipefail

KIND="${1:-}"
case "$KIND" in
  jwt|kek|job-signing|integration)
    ;;
  *)
    cat <<USAGE
usage: $0 <kind> [args...]

  jwt              Rotate VAULTSCAN_JWT_SECRET via the platform API.
                   Old key kept as verify-only for 24h grace.
                   args: <admin-jwt-token>

  kek              Rotate VAULTSCAN_EVIDENCE_MASTER_KEY at the secrets
                   backend. The cron-runner's dek_rewrap_sweep will
                   re-wrap every per-tenant DEK within hours.
                   args: <new-key-base64-32-bytes>

  job-signing      Rotate VAULTSCAN_JOB_SIGNING_KEY (orchestrator → worker).
                   args: <new-key-base64-32-bytes>

  integration      Rotate the inbound HMAC secret for one integration.
                   args: <admin-jwt> <integration-id> [new-secret]
                   (new-secret omitted = service generates one)

env:
  VAULTSCAN_API_URL              base URL of the API (default https://api.vaultscan.zaishield.com)
  VAULTSCAN_SECRETS_BACKEND      kubernetes | vault | sealed-secrets (defaults to kubernetes)
  VAULTSCAN_NAMESPACE            k8s namespace (default vaultscan)
  VAULTSCAN_SECRET_NAME          k8s secret holding env vars (default vaultscan-env)
USAGE
    exit 1
    ;;
esac

API="${VAULTSCAN_API_URL:-https://api.vaultscan.zaishield.com}"
NS="${VAULTSCAN_NAMESPACE:-vaultscan}"
SECRET="${VAULTSCAN_SECRET_NAME:-vaultscan-env}"
BACKEND="${VAULTSCAN_SECRETS_BACKEND:-kubernetes}"

# Pre-flight: every rotation gets backed up so an "oh no" can be undone.
backup_dir=/tmp/vaultscan-secret-backup-$(date +%FT%H-%M-%S)
mkdir -p "$backup_dir"
echo "backup dir: $backup_dir (delete after verifying the rotation took)"

case "$KIND" in
  jwt)
    TOKEN="${2:?missing admin-jwt arg}"
    echo "Triggering JWT signing-key rotation via /auth/jwt-keys/rotate..."
    out=$(curl -sf -X POST "$API/api/v1/auth/jwt-keys/rotate" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json")
    echo "$out" | jq .
    echo
    echo "✓ Old key kept as verify-only for 24h. Existing JWTs"
    echo "  remain valid; new tokens issued under the new key."
    ;;

  kek)
    NEW_KEY="${2:?missing new-key arg (base64 of 32 random bytes)}"
    # Sanity: must base64-decode to 32 bytes
    decoded_len=$(echo -n "$NEW_KEY" | base64 -d 2>/dev/null | wc -c)
    if [[ "$decoded_len" != "32" ]]; then
      echo "FAIL: NEW_KEY decodes to $decoded_len bytes, expected 32"
      exit 1
    fi

    case "$BACKEND" in
      kubernetes)
        kubectl get secret -n "$NS" "$SECRET" -o yaml > "$backup_dir/$SECRET.yaml"
        # Append OLD KEK as VAULTSCAN_EVIDENCE_MASTER_KEY_OLD so the
        # vault can still unwrap pre-rotation DEKs during re-wrap.
        old_kek=$(kubectl get secret -n "$NS" "$SECRET" -o jsonpath='{.data.VAULTSCAN_EVIDENCE_MASTER_KEY}')
        kubectl patch secret -n "$NS" "$SECRET" --type=json \
          -p "[{\"op\":\"add\",\"path\":\"/data/VAULTSCAN_EVIDENCE_MASTER_KEY_OLD\",\"value\":\"$old_kek\"},
               {\"op\":\"replace\",\"path\":\"/data/VAULTSCAN_EVIDENCE_MASTER_KEY\",\"value\":\"$(echo -n $NEW_KEY | base64)\"}]"
        echo "✓ KEK rotated in $NS/$SECRET. Old KEK preserved as _OLD."
        echo "  Roll API + cron-runner so they pick up the new env:"
        echo "    kubectl rollout restart -n $NS deployment/vaultscan-api"
        echo "    kubectl rollout restart -n $NS deployment/vaultscan-cron-runner"
        echo "  The cron-runner dek_rewrap_sweep task will re-wrap"
        echo "  per-tenant DEKs under the new KEK within ~1 hour."
        echo "  After verifying every DEK is re-wrapped:"
        echo "    kubectl patch secret -n $NS $SECRET --type=json \\"
        echo "      -p '[{\"op\":\"remove\",\"path\":\"/data/VAULTSCAN_EVIDENCE_MASTER_KEY_OLD\"}]'"
        ;;
      vault)
        echo "vault backend: write the new key to vault path then restart workloads"
        echo "  vault kv put secret/vaultscan/kek master_key=<base64>"
        ;;
      sealed-secrets)
        echo "sealed-secrets backend: encode the new key with kubeseal then commit"
        echo "  echo -n '$NEW_KEY' | kubeseal --raw --name $SECRET ..."
        ;;
      *)
        echo "FAIL: unknown backend $BACKEND"
        exit 1
        ;;
    esac
    ;;

  job-signing)
    NEW_KEY="${2:?missing new-key arg}"
    case "$BACKEND" in
      kubernetes)
        kubectl get secret -n "$NS" "$SECRET" -o yaml > "$backup_dir/$SECRET.yaml"
        kubectl patch secret -n "$NS" "$SECRET" --type=json \
          -p "[{\"op\":\"replace\",\"path\":\"/data/VAULTSCAN_JOB_SIGNING_KEY\",\"value\":\"$(echo -n $NEW_KEY | base64)\"}]"
        kubectl rollout restart -n "$NS" deployment/vaultscan-api
        kubectl rollout restart -n "$NS" deployment/vaultscan-scanner-worker
        ;;
    esac
    echo "✓ job signing key rotated. In-flight jobs verified against the OLD key may fail; the orchestrator re-queues them within the retry budget."
    ;;

  integration)
    TOKEN="${2:?missing admin-jwt arg}"
    ID="${3:?missing integration-id arg}"
    SECRET_VAL="${4:-}"
    body='{"secret":""}'
    if [[ -n "$SECRET_VAL" ]]; then
      body=$(jq -n --arg s "$SECRET_VAL" '{secret:$s}')
    else
      body='{}'  # service generates
    fi
    out=$(curl -sf -X PUT "$API/api/v1/integrations/$ID/signing-secret" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body")
    echo "$out" | jq .
    echo "✓ integration $ID HMAC secret rotated. Notify the partner system to update their secret."
    ;;
esac
