# Katana — web crawler that feeds URLs into ffuf/nuclei. JSON output
# via -jc keeps the downstream parser pipeline simple.
FROM projectdiscovery/katana:latest
USER 1001
ENTRYPOINT ["/usr/local/bin/katana"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
