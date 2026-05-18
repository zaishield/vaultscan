FROM greenbone/openvas-scanner:stable
# DELIBERATELY no USER directive. OpenVAS needs CAP_NET_RAW for
# raw-socket port scans + ICMP. The scanner-tool pod running
# this image MUST grant NET_RAW + NET_BIND_SERVICE; the chart's
# scanner container security context already adds NET_BIND_SERVICE
# via _security.tpl.scannerContainerSecurityContext.
ENTRYPOINT ["openvas"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
