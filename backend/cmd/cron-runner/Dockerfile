# Multi-stage build for the cron-runner — the leader-elected background
# worker that runs every periodic task in the platform (SLA sweep, DEK
# rotation + re-wrap, audit verify-deep, partition maintenance, SIEM
# shipping, integration DLQ depth refresh, agent telemetry rollup,
# scheduled report generation).
#
# Without this binary running, the platform silently degrades: SLA
# breaches don't auto-flag, DEKs don't rotate, audit chain forensics
# don't run, partitions aren't pre-created, etc.

FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/cron-runner \
    ./cmd/cron-runner

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/cron-runner /app/cron-runner

USER 65532:65532
WORKDIR /app

# Admin/metrics port (Prometheus scrape + /healthz). The runtime
# default in cmd/cron-runner/main.go matches this.
EXPOSE 9091

ENTRYPOINT ["/app/cron-runner"]
