# Gitleaks — secret scanner for git repos + tarballs. Pairs with the
# DevSecOps profile + the internal-network code-review scan.
FROM zricethezav/gitleaks:latest
USER 1000
ENTRYPOINT ["gitleaks"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
