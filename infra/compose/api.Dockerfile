FROM golang:1.22-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./backend/
RUN cd backend && go mod download
COPY backend ./backend
RUN cd backend && CGO_ENABLED=0 go build -o /out/api      ./cmd/api
RUN cd backend && CGO_ENABLED=0 go build -o /out/migrate  ./cmd/migrate
RUN cd backend && CGO_ENABLED=0 go build -o /out/seed     ./cmd/seed

FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/api     /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
COPY --from=build /out/seed    /usr/local/bin/seed
COPY backend/migrations /backend/migrations
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
