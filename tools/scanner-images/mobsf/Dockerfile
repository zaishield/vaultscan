FROM opensecurity/mobile-security-framework-mobsf:latest
# Django app; doesn't need root. Image's bundled `mobsf` user is
# uid 9901 (per upstream Dockerfile) but we coerce to 65532 so the
# scanner-tool pod's runAsNonRoot enforcement matches the rest of
# the fleet.
USER 65532
ENTRYPOINT ["python", "manage.py"]
