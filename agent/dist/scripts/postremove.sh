#!/bin/sh
# postremove — leave /var/lib/vaultscan-agent in place so operator can
# choose to purge separately. Reload systemd. Don't delete the user
# (their files might still own things outside our packaging).
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
