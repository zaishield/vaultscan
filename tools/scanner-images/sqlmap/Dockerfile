# sqlmap — SQL injection detection + exploitation. Tenants control
# the technique allow-list via agent_policies; defaults to read-only
# (--technique=B) so a default-config scan never modifies the target.
FROM python:3.12-alpine
RUN apk add --no-cache git ca-certificates \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && apk del git
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["python", "/opt/sqlmap/sqlmap.py"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
