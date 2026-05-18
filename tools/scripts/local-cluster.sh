#!/usr/bin/env bash
# local-cluster.sh — manage local kind clusters used by the
# Terraform `generic` flavor for dev / staging / uat / prod.
#
# Each environment gets its own kind cluster so they're fully
# isolated. Cluster name = "vaultscan-${ENV}"; kubeconfig context
# = "kind-vaultscan-${ENV}". The generic Terraform composition's
# tfvars files already point at those contexts.
#
# Usage:
#   ./local-cluster.sh up      <env>
#   ./local-cluster.sh down    <env>
#   ./local-cluster.sh status  [env]
#   ./local-cluster.sh up-all              # bring up all four
#   ./local-cluster.sh down-all            # destroy all four
#
# Resource budget per cluster (single control-plane + 2 workers):
#   dev:     ~2 GB RAM, ~2 cores
#   staging: ~3 GB RAM, ~3 cores
#   uat:     ~4 GB RAM, ~3 cores
#   prod:    ~6 GB RAM, ~4 cores  (bigger Postgres + multi-MinIO)
#
# Running all four concurrently needs ~16 GB RAM free. If your
# laptop can't, bring them up one at a time.

set -euo pipefail

ENVS=(dev staging uat prod)

require() {
  for tool in kind kubectl docker; do
    command -v "$tool" >/dev/null 2>&1 || {
      echo "FAIL: $tool not in PATH"; exit 1
    }
  done
}

cluster_name() { echo "vaultscan-${1}"; }
context_name() { echo "kind-vaultscan-${1}"; }

# Per-environment kind config. Dev gets a single node; the higher
# envs get 1 control-plane + 2 workers so HA-style scheduling
# (PDB minAvailable, topology spread, anti-affinity) is exercisable.
write_kind_config() {
  local env="$1"
  local file="$2"
  case "$env" in
    dev)
      cat > "$file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: vaultscan-${env}
nodes:
  - role: control-plane
EOF
      ;;
    *)
      cat > "$file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: vaultscan-${env}
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - { containerPort: 80,    hostPort: ${HOST_HTTP_PORT:-80},   protocol: TCP }
      - { containerPort: 443,   hostPort: ${HOST_HTTPS_PORT:-443}, protocol: TCP }
  - role: worker
  - role: worker
EOF
      ;;
  esac
}

up_one() {
  local env="$1"
  local name; name="$(cluster_name "$env")"
  if kind get clusters 2>/dev/null | grep -qx "$name"; then
    echo "✓ $name already exists"
  else
    local cfg; cfg="$(mktemp)"
    write_kind_config "$env" "$cfg"
    echo "Creating kind cluster $name ..."
    kind create cluster --config "$cfg"
    rm -f "$cfg"
  fi
  kubectl config use-context "$(context_name "$env")" >/dev/null
  echo "✓ context: $(context_name "$env")"
  # For non-dev envs, install ingress-nginx so the chart's Ingress
  # resources resolve. Dev disables ingress so it skips this.
  if [[ "$env" != "dev" ]]; then
    if ! kubectl get ns ingress-nginx >/dev/null 2>&1; then
      echo "Installing ingress-nginx ..."
      kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/kind/deploy.yaml
      kubectl wait --namespace ingress-nginx \
        --for=condition=ready pod --selector=app.kubernetes.io/component=controller \
        --timeout=180s
    fi
  fi
}

down_one() {
  local env="$1"
  local name; name="$(cluster_name "$env")"
  if kind get clusters 2>/dev/null | grep -qx "$name"; then
    echo "Deleting kind cluster $name ..."
    kind delete cluster --name "$name"
  else
    echo "✓ $name not running"
  fi
  # Also wipe the local Terraform workspace state for cleanliness.
  rm -rf "infra/terraform/environments/generic/terraform.tfstate.d/${env}"
}

status() {
  printf '%-12s  %-30s  %s\n' "ENV" "CLUSTER" "STATE"
  for e in "${ENVS[@]}"; do
    local name; name="$(cluster_name "$e")"
    if kind get clusters 2>/dev/null | grep -qx "$name"; then
      printf '%-12s  %-30s  %s\n' "$e" "$name" "running"
    else
      printf '%-12s  %-30s  %s\n' "$e" "$name" "-"
    fi
  done
}

validate_env() {
  local env="$1"
  for e in "${ENVS[@]}"; do [[ "$e" == "$env" ]] && return 0; done
  echo "FAIL: env must be one of: ${ENVS[*]}"
  exit 1
}

main() {
  require
  cmd="${1:-status}"; shift || true
  case "$cmd" in
    up)       validate_env "${1:-}"; up_one   "$1" ;;
    down)     validate_env "${1:-}"; down_one "$1" ;;
    up-all)   for e in "${ENVS[@]}"; do up_one   "$e"; done ;;
    down-all) for e in "${ENVS[@]}"; do down_one "$e"; done ;;
    status)   status ;;
    *) echo "usage: $0 up|down|status|up-all|down-all [env]"; exit 1 ;;
  esac
}
main "$@"
