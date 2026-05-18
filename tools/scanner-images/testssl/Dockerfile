# testssl.sh — comprehensive TLS audit. The official image ships a
# pinned bash + openssl combination.
FROM drwetter/testssl.sh:latest
USER 1000
ENTRYPOINT ["/home/testssl/testssl.sh"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
