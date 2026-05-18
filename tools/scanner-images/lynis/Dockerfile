FROM cisofy/lynis:latest
# DELIBERATELY no USER directive. Lynis is a host-audit tool that
# reads /etc, /proc, /var/log, and most security-relevant files
# require uid 0. The scanner-tool pod running this image MUST
# allow runAsNonRoot=false. Forcing USER 65532 would skip the
# majority of checks and silently produce a "clean" report.
ENTRYPOINT ["lynis"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
