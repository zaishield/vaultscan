# dirsearch — Python-based web path scanner with richer reporting
# than gobuster. Used for the web-VA profile alongside ffuf.
FROM python:3.12-alpine
RUN apk add --no-cache ca-certificates \
    && pip install --no-cache-dir dirsearch
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["dirsearch"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
