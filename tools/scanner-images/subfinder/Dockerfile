# Subfinder — ProjectDiscovery passive subdomain enumerator. Used by
# external_discovery profile. Produces JSONL on stdout with -oJ.
FROM projectdiscovery/subfinder:latest
USER 1001
ENTRYPOINT ["/usr/local/bin/subfinder"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
