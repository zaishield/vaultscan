FROM golang:1.26-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./backend/
RUN cd backend && go mod download
COPY backend ./backend
RUN cd backend && CGO_ENABLED=0 go build -o /out/cron-runner ./cmd/cron-runner

FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/cron-runner /usr/local/bin/cron-runner
EXPOSE 9091
ENTRYPOINT ["/usr/local/bin/cron-runner"]
