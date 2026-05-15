# restore-verify image — pulls latest backup from S3, restores into a
# sidecar Postgres, runs audit-chain verification.
#
# Bundles:
#   * postgres-client (psql, pg_restore, pg_isready)
#   * awscli v2 (S3 GET + LIST, supports --endpoint-url for MinIO/Ceph)
#   * gnupg + gunzip + curl
#
# The actual orchestration script is mounted by the CronJob's `args`
# block — keeping it in the chart (not the image) lets ops adjust the
# drill steps without rebuilding/repushing.

FROM alpine:3.19

RUN apk add --no-cache \
        postgresql16-client \
        py3-pip \
        bash \
        gzip \
        curl \
        ca-certificates \
        && pip install --no-cache-dir --break-system-packages awscli

USER 65532
WORKDIR /tmp

# The CronJob's args do all the work. ENTRYPOINT just guarantees the
# container survives long enough for kubectl exec / debug.
ENTRYPOINT ["/bin/sh"]
