# Analytics worker — subscribes to NATS + ingests into the analytics
# materialised views. No HTTP listener (only /healthz on a probe port).

FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/analytics-worker \
    ./cmd/analytics-worker

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/analytics-worker /app/analytics-worker

USER 65532:65532
WORKDIR /app
EXPOSE 8090

ENTRYPOINT ["/app/analytics-worker"]
