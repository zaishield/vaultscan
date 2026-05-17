FROM golang:1.26-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./backend/
RUN cd backend && go mod download
COPY backend ./backend

# The dev runner shells out to host binaries if installed. We include a
# couple of common, small ones (nmap) so demos can produce real output.
RUN cd backend && CGO_ENABLED=0 go build -o /out/scanner-worker ./cmd/scanner-worker

FROM alpine:3.19
RUN apk add --no-cache ca-certificates nmap
COPY --from=build /out/scanner-worker /usr/local/bin/scanner-worker
ENTRYPOINT ["/usr/local/bin/scanner-worker"]
