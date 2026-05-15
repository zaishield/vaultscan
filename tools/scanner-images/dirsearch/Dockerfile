# dirsearch — Python-based web path scanner with richer reporting
# than gobuster. Used for the web-VA profile alongside ffuf.
FROM python:3.12-alpine
RUN apk add --no-cache ca-certificates \
    && pip install --no-cache-dir dirsearch
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["dirsearch"]
