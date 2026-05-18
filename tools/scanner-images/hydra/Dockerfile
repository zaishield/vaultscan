# THC Hydra — password-spray tester. Strictly allowlisted by tenant
# policy (default deny); blueprint § marks this as the most-dangerous
# tool we ship so policy enforcement is the primary protection.
FROM alpine:3.19
RUN apk add --no-cache hydra ca-certificates
RUN adduser -D -u 10001 vaultscan
USER vaultscan
ENTRYPOINT ["hydra"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
