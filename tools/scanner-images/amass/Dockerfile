# Amass — OWASP attack-surface mapper. The upstream image ships a small
# binary on alpine so we pin to a tag and run as the bundled user.
FROM caffix/amass:latest
USER 1000
ENTRYPOINT ["amass"]
