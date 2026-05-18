FROM aquasec/trivy:latest
# Trivy supports non-root execution. The chart's scanner-tool pod
# enforces runAsNonRoot=true at pod level; the explicit USER here
# is defense in depth.
USER 65532
ENTRYPOINT ["/usr/local/bin/trivy"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
