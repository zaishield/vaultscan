SHELL := /bin/bash
.PHONY: help bootstrap up down restart logs migrate seed test backend-build agent-build frontend-build vet

help:
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/	/' | column -t -s'	'

bootstrap: ## Build images and bring up the stack
	cd infra/compose && docker compose build && docker compose up -d
	$(MAKE) migrate

up: ## Start the local stack
	cd infra/compose && docker compose up -d

down: ## Tear down the local stack
	cd infra/compose && docker compose down

restart: down up ## Restart the local stack

logs: ## Tail logs
	cd infra/compose && docker compose logs -f --tail=200

migrate: ## Run pending migrations against local Postgres
	cd backend && VAULTSCAN_DATABASE_URL=postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable go run ./cmd/migrate -dir migrations

seed: ## Insert demo tenants/engagements/findings
	cd backend && VAULTSCAN_DATABASE_URL=postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable go run ./cmd/seed || echo "seed binary not yet built; uses default migrations seed"

backend-build: ## Build all Go binaries
	cd backend && CGO_ENABLED=0 go build ./...

agent-build: ## Build the internal agent
	cd agent && CGO_ENABLED=0 go build ./...

frontend-build: ## Build the React portal
	cd frontend && npm install --silent && npm run build

vet: ## Run go vet across both modules
	cd backend && go vet ./...
	cd agent && go vet ./...

test: ## Run all unit tests
	cd backend && go test ./...
	cd agent && go test ./...
