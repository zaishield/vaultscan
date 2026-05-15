FROM alpine:3.19
RUN apk add --no-cache nmap nmap-scripts ca-certificates
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["/usr/bin/nmap"]
