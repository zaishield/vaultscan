# Multi-stage build for the scanner-worker.
#
# Stage 1 — build the binary inside golang:1.26-alpine.
# Stage 2 — distroless/static-debian12 nonroot.
#
# The worker does NOT need any scanner tools installed in its own
# image when VAULTSCAN_SCANNER_RUNNER=k8s — each tool runs in its own
# Job pod with the tool's dedicated image (tools/scanner-images/<tool>/).
# When RUNNER=local (dev only), the worker exec's against PATH; that
# image variant is the responsibility of the dev compose stack.

FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/scanner-worker \
    ./cmd/scanner-worker

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/scanner-worker /app/scanner-worker

USER 65532:65532
WORKDIR /app

ENTRYPOINT ["/app/scanner-worker"]
