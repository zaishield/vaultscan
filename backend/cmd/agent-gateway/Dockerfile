# Multi-stage build for the agent-gateway. Same pattern as backend/Dockerfile
# but for cmd/agent-gateway. Distinct image because:
#   1. Smaller binary (no API handlers wired in).
#   2. Different ports (8443 default).
#   3. Production runs it on a separate node pool / NetworkPolicy bind.

FROM golang:1.25-alpine AS build

WORKDIR /src

# The agent-gateway lives inside the backend module; copy the whole
# module so the gateway can compile against shared internal packages.
COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/agent-gateway \
    ./cmd/agent-gateway

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/agent-gateway /app/agent-gateway

USER 65532:65532
WORKDIR /app
EXPOSE 8443

ENTRYPOINT ["/app/agent-gateway"]
