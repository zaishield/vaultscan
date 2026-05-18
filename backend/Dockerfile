# Multi-stage build for the API control plane.
#
# Stage 1 — build inside golang:1.26-alpine, vendor go.sum, compile static.
# Stage 2 — copy the binary into a distroless static base (no shell, no
# package manager, no setuid binaries).
#
# The image ships three binaries:
#   /app/api     — the HTTP control plane (default ENTRYPOINT)
#   /app/migrate — schema migrator (used by the helm pre-install Job)
#   /app/seed    — idempotent seed runner (used by tools)
#
# Migrations SQL files are baked in at /app/migrations so the migration
# Job doesn't need to mount a configmap. The helm chart's migrations Job
# overrides ENTRYPOINT to /app/migrate.
#
# Production deployments tag the resulting image with the git SHA + a
# SemVer release tag, then push to registry.zaishield.com/vaultscan/api
# and sign with cosign (Blueprint §27.5).

FROM golang:1.26-alpine AS build

WORKDIR /src

# Bring in module manifests first so docker build cache reuses the
# `go mod download` layer when only source files change.
COPY go.mod go.sum ./
RUN go mod download

COPY . ./

# CGO disabled for fully-static binary; needed for distroless static.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=$(date -u +%Y%m%dT%H%M%SZ)" \
    -o /out/api \
    ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/migrate \
    ./cmd/migrate
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/seed \
    ./cmd/seed

# Migrations are bundled into the image so the chart's migrations-job
# doesn't have to mount a configmap of SQL files.
RUN cp -r migrations /out/migrations

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api        /app/api
COPY --from=build /out/migrate    /app/migrate
COPY --from=build /out/seed       /app/seed
COPY --from=build /out/migrations /app/migrations

USER 65532:65532
WORKDIR /app
EXPOSE 8080

ENTRYPOINT ["/app/api"]
