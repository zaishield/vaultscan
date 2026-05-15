#!/bin/sh
# preinstall — create the dedicated unprivileged user the agent runs as.
# Idempotent: no-op when the user already exists. POSIX-sh only so the
# same script ships into deb + rpm without bash dependency.

set -e

# getent existence is the deb-vs-rpm friendly way to check; both
# package families have it.
if ! getent passwd vaultscan >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home \
                --shell /usr/sbin/nologin \
                --comment "VAULTSCAN agent" \
                vaultscan
    elif command -v adduser >/dev/null 2>&1; then
        # Debian-old adduser variant.
        adduser --system --no-create-home --shell /usr/sbin/nologin \
                --group vaultscan
    fi
fi
