FROM toniblyx/prowler:latest
# AWS posture audit — reads creds from env / mounted ~/.aws.
# Doesn't need any privileged caps.
USER 65532
ENTRYPOINT ["prowler"]

# Scanner tools run as one-shot Kubernetes Jobs, not long-lived
# services. HEALTHCHECK NONE explicitly opts out of the default
# Docker healthcheck so a scheduled "check the tool is alive"
# from a CRI or sidecar can't mis-classify a long-running scan
# as a hung process and kill it.
HEALTHCHECK NONE
