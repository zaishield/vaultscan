FROM toniblyx/prowler:latest
# AWS posture audit — reads creds from env / mounted ~/.aws.
# Doesn't need any privileged caps.
USER 65532
ENTRYPOINT ["prowler"]
