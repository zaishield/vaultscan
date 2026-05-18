FROM specterops/bloodhound:latest
# AD-recon tool; the bundled UI server doesn't bind privileged ports.
USER 65532
ENTRYPOINT ["bloodhound"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
