# Gobuster — directory / DNS / vhost brute force. Same niche as ffuf
# with a slightly different output shape; we keep both so engagements
# can pick the one that matches the customer's wordlist preference.
FROM ghcr.io/oj/gobuster:latest
USER 1001
ENTRYPOINT ["gobuster"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
