SHELL := /bin/bash
COMPOSE := docker compose -f infra/compose/docker-compose.yml

.PHONY: help bootstrap doctor up down restart logs migrate seed urls reset \
        test backend-build agent-build frontend-build vet integration-test

help: ## Show this help
	@awk -F':.*##' '/^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------------
# Local stack lifecycle (container-only — no host Go/Node required)
# ----------------------------------------------------------------------------

bootstrap: doctor up wait-db migrate seed urls ## Bring up the full stack from a cold start

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

up: ## Build images and bring up the long-running services
	$(COMPOSE) up -d --build postgres opensearch minio keycloak nats
	$(COMPOSE) build api agent-gateway portal
	$(COMPOSE) up -d api agent-gateway portal

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
	@echo "  Portal     http://localhost:5173"
	@echo "  API        http://localhost:8080/healthz"
	@echo "  Agent GW   http://localhost:8443"
	@echo "  Keycloak   http://localhost:8081  (admin / admin)"
	@echo "  MinIO      http://localhost:9001  (vaultscan / vaultscan-dev-secret)"
	@echo "  OpenSearch http://localhost:9200"
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
	cd backend && VAULTSCAN_TEST_DATABASE_URL=postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable \
	  go test -tags=integration -count=1 -v ./test/integration/...
