# httpx — fast HTTP toolkit. Probes live hosts after subfinder/dnsx,
# captures status code + title + tech stack as JSONL.
FROM projectdiscovery/httpx:latest
USER 1001
ENTRYPOINT ["/usr/local/bin/httpx"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
