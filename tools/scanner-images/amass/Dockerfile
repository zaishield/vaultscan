# Amass — OWASP attack-surface mapper. The upstream image ships a small
# binary on alpine so we pin to a tag and run as the bundled user.
FROM caffix/amass:latest
USER 1000
ENTRYPOINT ["amass"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
