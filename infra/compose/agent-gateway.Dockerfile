FROM golang:1.22-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./backend/
RUN cd backend && go mod download
COPY backend ./backend
RUN cd backend && CGO_ENABLED=0 go build -o /out/agent-gateway ./cmd/agent-gateway

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /out/agent-gateway /usr/local/bin/
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/agent-gateway"]
