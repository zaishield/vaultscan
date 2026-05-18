SHELL := /bin/bash
COMPOSE := docker compose --env-file .env -f infra/compose/docker-compose.yml

# Effective host ports. Override at the make invocation or via .env at the
# repo root (docker-compose loads .env automatically via the --env-file flag
# above, and the Makefile's port-collision check below reads them via shell).
VAULTSCAN_PORTAL_PORT         ?= 5173
VAULTSCAN_API_PORT            ?= 8080
VAULTSCAN_AGENT_GATEWAY_PORT  ?= 8443
VAULTSCAN_KEYCLOAK_PORT       ?= 8081
VAULTSCAN_POSTGRES_PORT       ?= 5432
VAULTSCAN_OPENSEARCH_PORT     ?= 9200
VAULTSCAN_MINIO_PORT          ?= 9000
VAULTSCAN_MINIO_CONSOLE_PORT  ?= 9001
VAULTSCAN_NATS_PORT           ?= 4222
VAULTSCAN_NATS_MON_PORT       ?= 8222

.PHONY: help bootstrap doctor up down restart logs migrate seed urls reset \
        env check-ports wait-db \
        test backend-build agent-build frontend-build vet integration-test

help: ## Show this help
	@awk -F':.*##' '/^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------------
# Local stack lifecycle (container-only — no host Go/Node required)
# ----------------------------------------------------------------------------

bootstrap: doctor env check-ports up wait-db migrate seed urls ## Bring up the full stack from a cold start

doctor: ## Verify Docker + Compose are available
	@docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || { \
	  echo "✗ Docker daemon not reachable. Start Docker Desktop (mac/win) or"; \
	  echo "  'sudo systemctl start docker' (linux)."; exit 1; }
	@docker compose version --short >/dev/null 2>&1 || { \
	  echo "✗ docker compose v2 plugin not found."; \
	  echo "  Install: apt-get install docker-compose-plugin  (or upgrade Docker Desktop)"; exit 1; }
	@printf "✓ docker %s, compose %s\n" \
	  "$$(docker version --format '{{.Server.Version}}')" \
	  "$$(docker compose version --short)"

env: ## Create .env from .env.example if it doesn't exist
	@if [ ! -f .env ]; then \
	  cp .env.example .env; \
	  echo "✓ created .env from .env.example (edit it to override defaults)"; \
	else \
	  echo "✓ .env present"; \
	fi

# Lists every host port the stack will publish and flags any that are
# already in use by something other than our own compose project. Tries
# lsof first (works in any environment), falls back to ss. Skips silently
# if neither is available.
check-ports: ## Warn if any host port the stack publishes is already taken
	@conflicts=""; \
	probe="none"; \
	if command -v lsof >/dev/null 2>&1; then probe="lsof"; \
	elif command -v ss >/dev/null 2>&1; then probe="ss"; \
	fi; \
	if [ "$$probe" = "none" ]; then \
	  echo "(skipping port-conflict check: install lsof or iproute2 to enable)"; \
	  exit 0; \
	fi; \
	port_holder() { \
	  port=$$1; \
	  case "$$probe" in \
	    lsof) lsof -nP -iTCP:$$port -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $$1; exit}';; \
	    ss)   ss -ltnp "( sport = :$$port )" 2>/dev/null | awk 'NR>1 {print; exit}';; \
	  esac; \
	}; \
	check_port() { \
	  port=$$1; name=$$2; \
	  holder=$$(port_holder $$port); \
	  if [ -z "$$holder" ]; then return 0; fi; \
	  who=$$(docker ps --filter "publish=$$port" --format '{{.Names}}' 2>/dev/null | head -1); \
	  if [ -n "$$who" ] && echo "$$who" | grep -qE '^vaultscan-'; then return 0; fi; \
	  detail="$$holder"; [ -n "$$who" ] && detail="container $$who"; \
	  echo "  ✗ port $$port ($$name) is in use — $$detail"; \
	  return 1; \
	}; \
	check_port $(VAULTSCAN_PORTAL_PORT)        portal        || conflicts="$$conflicts $(VAULTSCAN_PORTAL_PORT)"; \
	check_port $(VAULTSCAN_API_PORT)           api           || conflicts="$$conflicts $(VAULTSCAN_API_PORT)"; \
	check_port $(VAULTSCAN_AGENT_GATEWAY_PORT) agent-gateway || conflicts="$$conflicts $(VAULTSCAN_AGENT_GATEWAY_PORT)"; \
	check_port $(VAULTSCAN_KEYCLOAK_PORT)      keycloak      || conflicts="$$conflicts $(VAULTSCAN_KEYCLOAK_PORT)"; \
	check_port $(VAULTSCAN_POSTGRES_PORT)      postgres      || conflicts="$$conflicts $(VAULTSCAN_POSTGRES_PORT)"; \
	check_port $(VAULTSCAN_OPENSEARCH_PORT)    opensearch    || conflicts="$$conflicts $(VAULTSCAN_OPENSEARCH_PORT)"; \
	check_port $(VAULTSCAN_MINIO_PORT)         minio         || conflicts="$$conflicts $(VAULTSCAN_MINIO_PORT)"; \
	check_port $(VAULTSCAN_MINIO_CONSOLE_PORT) minio-console || conflicts="$$conflicts $(VAULTSCAN_MINIO_CONSOLE_PORT)"; \
	check_port $(VAULTSCAN_NATS_PORT)          nats          || conflicts="$$conflicts $(VAULTSCAN_NATS_PORT)"; \
	check_port $(VAULTSCAN_NATS_MON_PORT)      nats-monitor  || conflicts="$$conflicts $(VAULTSCAN_NATS_MON_PORT)"; \
	if [ -n "$$conflicts" ]; then \
	  echo ""; \
	  echo "Override the colliding port(s) and retry. Examples:"; \
	  echo "  VAULTSCAN_OPENSEARCH_PORT=19200 make bootstrap"; \
	  echo "  echo VAULTSCAN_OPENSEARCH_PORT=19200 >> .env && make bootstrap"; \
	  echo ""; \
	  exit 1; \
	fi; \
	echo "✓ host ports clear"

up: ## Build images and bring up the long-running services
	$(COMPOSE) up -d --build postgres opensearch minio keycloak nats
	$(COMPOSE) build api agent-gateway portal analytics-worker
	$(COMPOSE) up -d api agent-gateway portal analytics-worker

wait-db: ## Block until Postgres is accepting connections
	@printf "Waiting for Postgres "
	@for i in $$(seq 1 90); do \
	  if $(COMPOSE) exec -T postgres pg_isready -U vaultscan -d vaultscan >/dev/null 2>&1; then \
	    echo " ready"; exit 0; \
	  fi; printf "."; sleep 1; \
	done; echo " timeout"; exit 1

migrate: ## Run pending schema migrations (idempotent)
	$(COMPOSE) run --rm migrate

seed: ## Insert demo distributor / MSSP / tenant / engagement / findings
	$(COMPOSE) run --rm seed

urls: ## Print local URLs once the stack is up
	@echo
	@echo "VAULTSCAN is up:"
	@echo "  Portal     http://localhost:$(VAULTSCAN_PORTAL_PORT)"
	@echo "  API        http://localhost:$(VAULTSCAN_API_PORT)/healthz"
	@echo "  Agent GW   http://localhost:$(VAULTSCAN_AGENT_GATEWAY_PORT)"
	@echo "  Keycloak   http://localhost:$(VAULTSCAN_KEYCLOAK_PORT)  (admin / admin)"
	@echo "  MinIO      http://localhost:$(VAULTSCAN_MINIO_CONSOLE_PORT)  (vaultscan / vaultscan-dev-secret)"
	@echo "  OpenSearch http://localhost:$(VAULTSCAN_OPENSEARCH_PORT)"
	@echo
	@echo "Default credentials: docs/operations/local-dev.md"

down: ## Stop the stack (keeps volumes)
	$(COMPOSE) down

restart: down up ## Restart the stack

reset: ## Stop the stack AND wipe all data volumes (destructive)
	$(COMPOSE) down -v
	@rm -rf /tmp/vaultscan-evidence /tmp/vaultscan-agent 2>/dev/null || true
	@echo "✓ all VAULTSCAN volumes removed"

logs: ## Tail logs from every service
	$(COMPOSE) logs -f --tail=200

# ----------------------------------------------------------------------------
# Build / test (require Go / Node on host — for hacking, not for deployment)
# ----------------------------------------------------------------------------

backend-build: ## Build all Go backend binaries
	cd backend && CGO_ENABLED=0 go build ./...

agent-build: ## Build the internal agent binary
	cd agent && CGO_ENABLED=0 go build ./...

frontend-build: ## Build the portal production bundle
	cd frontend && npm install --silent && npm run build

vet: ## Run go vet across both Go modules
	cd backend && go vet ./...
	cd agent   && go vet ./...

test: ## Run all unit tests (host Go required)
	cd backend && go test ./...
	cd agent   && go test ./...

integration-test: ## Run integration tests against the live compose Postgres
	$(COMPOSE) up -d postgres
	@$(MAKE) --no-print-directory wait-db
	$(COMPOSE) run --rm migrate
	cd backend && VAULTSCAN_TEST_DATABASE_URL=postgres://vaultscan:vaultscan@localhost:$(VAULTSCAN_POSTGRES_PORT)/vaultscan?sslmode=disable \
	  go test -tags=integration -count=1 -v ./test/integration/...

# ----------------------------------------------------------------------------
# Helm — per-environment install / upgrade
# ----------------------------------------------------------------------------
#
# Each target installs the chart against the current kubectl context with
# the corresponding values overlay. NAMESPACE defaults to "vaultscan-$env"
# so dev/staging/uat/prod can coexist in one cluster for testing.
#
# Production usage:
#   kubectl config use-context prod-eu
#   make helm-prod EXTRA="--set databases.external.postgresURL=<DSN>"

HELM ?= helm
RELEASE ?= vaultscan
CHART := infra/helm/vaultscan

.PHONY: helm-lint helm-template-dev helm-template-staging helm-template-uat helm-template-prod \
        helm-dev helm-staging helm-uat helm-prod

helm-lint: ## helm lint the chart against every values overlay
	$(HELM) lint $(CHART)
	$(HELM) lint $(CHART) -f $(CHART)/values-dev.yaml
	$(HELM) lint $(CHART) -f $(CHART)/values-staging.yaml
	$(HELM) lint $(CHART) -f $(CHART)/values-uat.yaml
	$(HELM) lint $(CHART) -f $(CHART)/values-prod.yaml

helm-template-dev: ## Render the chart with the dev overlay
	$(HELM) template $(RELEASE) $(CHART) -f $(CHART)/values-dev.yaml --debug

helm-template-staging: ## Render the chart with the staging overlay
	$(HELM) template $(RELEASE) $(CHART) -f $(CHART)/values-staging.yaml --debug

helm-template-uat: ## Render the chart with the UAT overlay
	$(HELM) template $(RELEASE) $(CHART) -f $(CHART)/values-uat.yaml --debug

helm-template-prod: ## Render the chart with the production overlay
	$(HELM) template $(RELEASE) $(CHART) -f $(CHART)/values-prod.yaml --debug

helm-dev: NAMESPACE ?= vaultscan-dev
helm-dev: ## Install/upgrade dev
	$(HELM) upgrade --install $(RELEASE) $(CHART) -n $(NAMESPACE) --create-namespace \
	  -f $(CHART)/values-dev.yaml $(EXTRA)

helm-staging: NAMESPACE ?= vaultscan-staging
helm-staging: ## Install/upgrade staging
	$(HELM) upgrade --install $(RELEASE) $(CHART) -n $(NAMESPACE) --create-namespace \
	  -f $(CHART)/values-staging.yaml $(EXTRA)

helm-uat: NAMESPACE ?= vaultscan-uat
helm-uat: ## Install/upgrade UAT
	$(HELM) upgrade --install $(RELEASE) $(CHART) -n $(NAMESPACE) --create-namespace \
	  -f $(CHART)/values-uat.yaml $(EXTRA)

helm-prod: NAMESPACE ?= vaultscan
helm-prod: ## Install/upgrade production — operator MUST review the diff first
	@printf '\033[1;33m!! PRODUCTION INSTALL — review diff before confirming\033[0m\n'
	-$(HELM) diff upgrade $(RELEASE) $(CHART) -n $(NAMESPACE) -f $(CHART)/values-prod.yaml $(EXTRA)
	@read -r -p "Type 'yes' to proceed with helm upgrade: " ans && [ "$$ans" = "yes" ]
	$(HELM) upgrade --install $(RELEASE) $(CHART) -n $(NAMESPACE) --create-namespace \
	  -f $(CHART)/values-prod.yaml $(EXTRA)

# ----------------------------------------------------------------------------
# Terraform / OpenTofu — cloud-agnostic IaC
# ----------------------------------------------------------------------------
#
# Usage:
#   make tf-init   CLOUD=aws ENV=dev
#   make tf-plan   CLOUD=aws ENV=prod
#   make tf-apply  CLOUD=gcp ENV=staging
#   make tf-destroy CLOUD=generic ENV=dev
#
# CLOUD must be one of: aws | gcp | azure | generic
# ENV   must be one of: dev | staging | uat | prod
#
# Defaults to OpenTofu (TF=tofu). Override TF=terraform to use HashiCorp's
# binary. The compositions are byte-identical between the two.

TF       ?= tofu
TF_DIR    = infra/terraform/environments/$(CLOUD)
TFVARS    = $(TF_DIR)/$(ENV).tfvars

.PHONY: tf-init tf-fmt tf-validate tf-plan tf-apply tf-destroy tf-output

tf-fmt: ## Format every Terraform file under infra/terraform/
	$(TF) -chdir=infra/terraform fmt -recursive

tf-validate: tf-guard ## Validate the active CLOUD composition (no apply)
	$(TF) -chdir=$(TF_DIR) init -backend=false
	$(TF) -chdir=$(TF_DIR) validate

tf-init: tf-guard ## tofu init (initializes the backend)
	$(TF) -chdir=$(TF_DIR) init

tf-plan: tf-guard tfvars-guard ## tofu plan -var-file=ENV.tfvars
	$(TF) -chdir=$(TF_DIR) plan -var-file=$(ENV).tfvars

tf-apply: tf-guard tfvars-guard ## tofu apply for non-prod; production prompts
	@if [ "$(ENV)" = "prod" ]; then \
	  printf '\033[1;31m!! PRODUCTION TERRAFORM APPLY — review plan first\033[0m\n'; \
	  $(TF) -chdir=$(TF_DIR) plan -var-file=$(ENV).tfvars; \
	  read -r -p "Type 'yes' to apply: " ans && [ "$$ans" = "yes" ] || exit 1; \
	fi
	$(TF) -chdir=$(TF_DIR) apply -var-file=$(ENV).tfvars

tf-destroy: tf-guard tfvars-guard ## tofu destroy — production refuses
	@if [ "$(ENV)" = "prod" ]; then \
	  printf '\033[1;31m!! refusing tf-destroy on prod via Makefile. Run tofu destroy manually after confirming with on-call.\033[0m\n'; \
	  exit 1; \
	fi
	$(TF) -chdir=$(TF_DIR) destroy -var-file=$(ENV).tfvars

tf-output: tf-guard ## Show outputs of the active composition
	$(TF) -chdir=$(TF_DIR) output

# Internal: refuse to run with a missing CLOUD or unsupported value.
tf-guard:
	@case "$(CLOUD)" in \
	  aws|gcp|azure|generic) : ;; \
	  *) echo "CLOUD must be one of: aws | gcp | azure | generic"; exit 1 ;; \
	esac

tfvars-guard:
	@case "$(ENV)" in \
	  dev|staging|uat|prod) : ;; \
	  *) echo "ENV must be one of: dev | staging | uat | prod"; exit 1 ;; \
	esac

# ----------------------------------------------------------------------------
# Local Terraform path — kind clusters + the generic flavor
# ----------------------------------------------------------------------------
#
# Each environment runs in its own kind cluster (vaultscan-${ENV}) +
# its own Terraform workspace, so dev/staging/uat/prod can coexist
# on one laptop without state collision.
#
# Resource budget per cluster (single CP + 2 workers for non-dev):
#   dev: 2GB / 2c     staging: 3GB / 3c
#   uat: 4GB / 3c     prod:    6GB / 4c
# Running all four at once needs ~16GB free.
#
# Usage:
#   make tf-local-up     ENV=dev         # creates kind cluster + tofu apply
#   make tf-local-down   ENV=dev         # tofu destroy + delete kind cluster
#   make tf-local-status                 # show all four cluster states
#   make tf-local-up-all                 # bring up dev+staging+uat+prod
#   make tf-local-down-all
#   make tf-local-portforward ENV=dev    # expose api/portal on localhost

LOCAL_TF_DIR = infra/terraform/environments/generic

.PHONY: tf-local-up tf-local-down tf-local-status tf-local-up-all tf-local-down-all tf-local-portforward

tf-local-status: ## Show kind-cluster status for every VaultScan env
	@./tools/scripts/local-cluster.sh status

tf-local-up: ## Create kind cluster for ENV + tofu apply against it
	@test -n "$(ENV)" || { echo "ENV must be one of: dev | staging | uat | prod"; exit 1; }
	./tools/scripts/local-cluster.sh up $(ENV)
	$(TF) -chdir=$(LOCAL_TF_DIR) init
	$(TF) -chdir=$(LOCAL_TF_DIR) workspace select -or-create $(ENV)
	$(TF) -chdir=$(LOCAL_TF_DIR) apply -var-file=$(ENV).tfvars \
	  -var=local_overrides_enabled=true -auto-approve

tf-local-down: ## tofu destroy ENV + delete kind cluster
	@test -n "$(ENV)" || { echo "ENV must be one of: dev | staging | uat | prod"; exit 1; }
	-$(TF) -chdir=$(LOCAL_TF_DIR) workspace select $(ENV) 2>/dev/null && \
	  $(TF) -chdir=$(LOCAL_TF_DIR) destroy -var-file=$(ENV).tfvars \
	    -var=local_overrides_enabled=true -auto-approve
	-$(TF) -chdir=$(LOCAL_TF_DIR) workspace select default 2>/dev/null
	-$(TF) -chdir=$(LOCAL_TF_DIR) workspace delete $(ENV) 2>/dev/null
	./tools/scripts/local-cluster.sh down $(ENV)

tf-local-up-all: ## Sequentially bring up all four local envs
	@for env in dev staging uat prod; do \
	  $(MAKE) --no-print-directory tf-local-up ENV=$$env; \
	done

tf-local-down-all: ## Tear down all four local envs
	@for env in dev staging uat prod; do \
	  $(MAKE) --no-print-directory tf-local-down ENV=$$env || true; \
	done

tf-local-portforward: ## kubectl port-forward api (8080) + portal (5173) for ENV
	@test -n "$(ENV)" || { echo "ENV must be one of: dev | staging | uat | prod"; exit 1; }
	@echo "ENV=$(ENV) — Ctrl-C to stop. API at http://localhost:8080, portal at http://localhost:5173"
	@kubectl --context kind-vaultscan-$(ENV) -n vaultscan port-forward svc/vaultscan-api    8080:8080 & \
	 kubectl --context kind-vaultscan-$(ENV) -n vaultscan port-forward svc/vaultscan-portal 5173:80   & \
	 wait

# ----------------------------------------------------------------------------
# Developer convenience + operator backup helpers (referenced by docs)
# ----------------------------------------------------------------------------

.PHONY: watch-api backup-snapshot restore-snapshot

watch-api: ## Hot-reload the API binary on every Go file change (dev only)
	@command -v reflex >/dev/null 2>&1 || { \
	  echo "reflex not installed. install with: go install github.com/cespare/reflex@latest"; exit 1; \
	}
	cd backend && reflex -r '\.go$$' -s -- sh -c 'go run ./cmd/api'

backup-snapshot: ## Take a verified pg_dump snapshot to /var/lib/vaultscan-snapshots/
	@command -v pg_dump >/dev/null 2>&1 || { echo "pg_dump not installed"; exit 1; }
	@test -n "$$VAULTSCAN_DATABASE_URL" || { echo "VAULTSCAN_DATABASE_URL not set"; exit 1; }
	mkdir -p /var/lib/vaultscan-snapshots
	@SNAP="/var/lib/vaultscan-snapshots/snap-$$(date +%FT%H-%M-%S).sql.gz"; \
	  echo "snapshot → $$SNAP"; \
	  pg_dump --no-owner --no-privileges --format=plain "$$VAULTSCAN_DATABASE_URL" \
	    | gzip > "$$SNAP"; \
	  sha256sum "$$SNAP" > "$$SNAP.sha256"; \
	  echo "✓ snapshot saved + sha256-attested"; \
	  ls -la "$$SNAP"

restore-snapshot: ## Restore from a snapshot file: make restore-snapshot SNAPSHOT_ID=<path>
	@test -n "$(SNAPSHOT_ID)" || { echo "SNAPSHOT_ID required (path to .sql.gz from make backup-snapshot)"; exit 1; }
	@test -f "$(SNAPSHOT_ID)" || { echo "SNAPSHOT_ID file not found: $(SNAPSHOT_ID)"; exit 1; }
	@test -n "$$VAULTSCAN_DATABASE_URL" || { echo "VAULTSCAN_DATABASE_URL not set"; exit 1; }
	@printf '\033[1;31m!! RESTORING — DESTRUCTIVE. Current DB contents will be replaced.\033[0m\n'
	@read -r -p "Type 'restore' to proceed: " ans && [ "$$ans" = "restore" ]
	gunzip -c "$(SNAPSHOT_ID)" | psql "$$VAULTSCAN_DATABASE_URL"
