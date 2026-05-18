#!/usr/bin/env bash
# deploy-verify.sh — spins a kind cluster, deploys the chart, asserts
# the API + portal pods become Ready and /healthz returns 200.
#
# Used by .github/workflows/helm-deploy-verify.yml on every PR. Can
# also be run locally for manual verification.
#
# Required tools: kind, kubectl, helm, docker.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
CHART="$ROOT/infra/helm/vaultscan"
CLUSTER="vaultscan-test"
NS="vaultscan"
TIMEOUT=300         # seconds for any wait

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    log "KEEP_CLUSTER=1 — leaving kind cluster $CLUSTER alive"
  else
    log "tearing down kind cluster"
    kind delete cluster --name "$CLUSTER" 2>/dev/null || true
    docker rm -f kind-registry 2>/dev/null || true
  fi
}
trap cleanup EXIT

# -- 1. Local registry + kind cluster --------------------------------------

if ! docker ps --format '{{.Names}}' | grep -q '^kind-registry$'; then
  log "starting local image registry on :5000"
  docker run -d --restart=always -p 5000:5000 --name kind-registry registry:2 >/dev/null
fi

if kind get clusters | grep -q "^$CLUSTER$"; then
  log "kind cluster $CLUSTER already exists — reusing"
else
  log "creating kind cluster"
  kind create cluster --config "$CHART/kind-cluster.yaml"
fi
docker network connect kind kind-registry 2>/dev/null || true

kubectl config use-context "kind-$CLUSTER"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# -- 2. Build + push the API image ----------------------------------------

log "building backend image"
docker build -t localhost:5000/vaultscan/api:kind-test \
  -f "$ROOT/backend/Dockerfile" "$ROOT/backend"
docker push localhost:5000/vaultscan/api:kind-test

# Optional companion images. Skip if their Dockerfile isn't present so
# the script works during partial migrations.
for image in agent-gateway portal analytics-worker cron-runner scanner-worker; do
  dockerfile=""
  context="$ROOT/backend"
  case "$image" in
    agent-gateway)    dockerfile="$ROOT/backend/cmd/agent-gateway/Dockerfile" ;;
    portal)           dockerfile="$ROOT/frontend/Dockerfile";       context="$ROOT/frontend" ;;
    analytics-worker) dockerfile="$ROOT/backend/cmd/analytics-worker/Dockerfile" ;;
    cron-runner)      dockerfile="$ROOT/backend/cmd/cron-runner/Dockerfile" ;;
    scanner-worker)   dockerfile="$ROOT/backend/cmd/scanner-worker/Dockerfile" ;;
  esac
  if [ -n "$dockerfile" ] && [ -f "$dockerfile" ]; then
    log "building $image image"
    docker build -t "localhost:5000/vaultscan/$image:kind-test" \
      -f "$dockerfile" "$context"
    docker push "localhost:5000/vaultscan/$image:kind-test"
  else
    log "skipping $image (no Dockerfile yet — using placeholder)"
    docker pull -q nginxinc/nginx-unprivileged:1.27-alpine >/dev/null
    docker tag nginxinc/nginx-unprivileged:1.27-alpine "localhost:5000/vaultscan/$image:kind-test"
    docker push -q "localhost:5000/vaultscan/$image:kind-test" >/dev/null
  fi
done

# -- 3. In-cluster Postgres --------------------------------------------------

log "deploying Postgres in-cluster"
kubectl apply -n "$NS" -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: { app: postgres }
  ports: [{ port: 5432, targetPort: 5432 }]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          env:
            - { name: POSTGRES_USER,     value: vaultscan }
            - { name: POSTGRES_PASSWORD, value: vaultscan }
            - { name: POSTGRES_DB,       value: vaultscan }
          ports: [{ containerPort: 5432 }]
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "vaultscan"] }
            initialDelaySeconds: 5
EOF
kubectl wait -n "$NS" --for=condition=available --timeout=120s deploy/postgres

# -- 4. helm install -------------------------------------------------------

PG_DSN="postgres://vaultscan:vaultscan@postgres.${NS}.svc.cluster.local:5432/vaultscan?sslmode=disable"

log "helm install"
helm upgrade --install vaultscan "$CHART" \
  --namespace "$NS" \
  -f "$CHART/values.kind.yaml" \
  --set "secrets.inline.databaseURL=$PG_DSN" \
  --set "databases.external.postgresURL=$PG_DSN" \
  --wait --timeout 5m

# -- 5. Pod readiness ------------------------------------------------------

log "waiting for API pod"
kubectl wait -n "$NS" --for=condition=available --timeout=${TIMEOUT}s \
  deploy -l app.kubernetes.io/component=api

# -- 6. /healthz check via port-forward ------------------------------------

log "port-forwarding API"
kubectl port-forward -n "$NS" svc/vaultscan-api 8080:8080 >/tmp/pf.log 2>&1 &
PF_PID=$!
sleep 3

log "GET /healthz"
HTTP=$(curl -s -o /tmp/health.body -w "%{http_code}" http://localhost:8080/healthz || echo 000)
kill $PF_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ "$HTTP" != "200" ]; then
  log "describe failing pods:"
  kubectl get pods -n "$NS"
  for pod in $(kubectl get pods -n "$NS" -l app.kubernetes.io/component=api -o name); do
    echo "===== $pod ====="
    kubectl describe -n "$NS" "$pod" | tail -40
    kubectl logs   -n "$NS" "$pod" --tail=80 || true
  done
  fail "/healthz returned HTTP $HTTP (body: $(cat /tmp/health.body))"
fi
log "/healthz: 200 OK"
log "deploy-verify SUCCESS"
