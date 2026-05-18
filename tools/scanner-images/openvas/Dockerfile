FROM greenbone/openvas-scanner:stable
# DELIBERATELY no USER directive. OpenVAS needs CAP_NET_RAW for
# raw-socket port scans + ICMP. The scanner-tool pod running
# this image MUST grant NET_RAW + NET_BIND_SERVICE; the chart's
# scanner container security context already adds NET_BIND_SERVICE
# via _security.tpl.scannerContainerSecurityContext.
ENTRYPOINT ["openvas"]
