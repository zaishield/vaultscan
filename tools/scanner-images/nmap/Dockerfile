FROM alpine:3.19
RUN apk add --no-cache nmap nmap-scripts ca-certificates
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["/usr/bin/nmap"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
