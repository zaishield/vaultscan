#!/bin/sh
# postinstall — reload systemd, optionally enable+start the unit.
# Honours installer policy: if /etc/vaultscan-agent/agent.yaml isn't
# fully filled (placeholder tenant_id / gateway_url), we don't start
# automatically; the operator runs `vaultscan-agent provision` first.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true

    # Don't auto-start if the config still has unfilled placeholders.
    if grep -q "REPLACE-ME-TENANT-ID" /etc/vaultscan-agent/agent.yaml 2>/dev/null; then
        echo "VAULTSCAN agent installed."
        echo "Edit /etc/vaultscan-agent/agent.yaml to set tenant_id +"
        echo "gateway_url + enrolment token, then:"
        echo "  systemctl enable --now vaultscan-agent"
    else
        systemctl enable vaultscan-agent || true
        systemctl restart vaultscan-agent || true
    fi
fi
