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
