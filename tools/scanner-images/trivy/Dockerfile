FROM aquasec/trivy:latest
# Trivy supports non-root execution. The chart's scanner-tool pod
# enforces runAsNonRoot=true at pod level; the explicit USER here
# is defense in depth.
USER 65532
ENTRYPOINT ["/usr/local/bin/trivy"]
