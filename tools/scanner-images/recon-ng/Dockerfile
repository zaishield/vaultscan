# recon-ng — OSINT framework. Fed by the external_discovery profile;
# its modules drive a lot of the §14 enrichment pipeline.
FROM python:3.12-alpine
RUN apk add --no-cache git build-base libffi-dev openssl-dev ca-certificates \
    && pip install --no-cache-dir recon-ng \
    && apk del build-base
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["recon-ng"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
