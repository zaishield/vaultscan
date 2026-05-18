# Naabu — port scanner from ProjectDiscovery. Faster than nmap for
# the discovery sweep; nmap re-runs against a tighter target set.
FROM projectdiscovery/naabu:latest
USER 1001
ENTRYPOINT ["/usr/local/bin/naabu"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
