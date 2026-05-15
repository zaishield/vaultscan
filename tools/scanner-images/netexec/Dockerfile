# NetExec — Active Directory / SMB / WinRM swiss army knife. Used by
# the internal_ad_review profile alongside bloodhound.
FROM python:3.12-alpine
RUN apk add --no-cache git build-base libffi-dev openssl-dev ca-certificates \
    && pip install --no-cache-dir netexec \
    && apk del build-base
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["nxc"]
