# SSLyze — TLS posture scanner. Used as a second opinion alongside
# testssl. Emits JSON via --json_out=-.
FROM python:3.12-alpine
RUN apk add --no-cache build-base libffi-dev openssl-dev ca-certificates \
    && pip install --no-cache-dir sslyze \
    && apk del build-base
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["sslyze"]
