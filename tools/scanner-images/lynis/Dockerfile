FROM cisofy/lynis:latest
# DELIBERATELY no USER directive. Lynis is a host-audit tool that
# reads /etc, /proc, /var/log, and most security-relevant files
# require uid 0. The scanner-tool pod running this image MUST
# allow runAsNonRoot=false. Forcing USER 65532 would skip the
# majority of checks and silently produce a "clean" report.
ENTRYPOINT ["lynis"]
