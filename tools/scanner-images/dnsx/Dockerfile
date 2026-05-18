# dnsx — DNS resolver / wildcard detector. Drives the discovery
# pipeline alongside subfinder + amass.
FROM projectdiscovery/dnsx:latest
USER 1001
ENTRYPOINT ["/usr/local/bin/dnsx"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
