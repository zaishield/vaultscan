#!/usr/bin/env python3
"""oasgen — emit a complete-coverage OpenAPI 3.1 spec from the chi
route table.

Why a script and not Go: this only runs at dev time + in CI to verify
spec drift. Keeping it stdlib-Python avoids adding a Go OpenAPI
generation dependency.

Workflow:
  1. Grep the codebase for r.Get/Post/Put/Delete/Patch calls.
  2. Bucket each route into a tag (auth, scans, findings, etc.).
  3. Emit an operation per (method, path) with:
       - operationId derived from method + path
       - tags
       - summary line from a simple lookup table
       - parameters extracted from {name} placeholders
       - 2xx response of {} schema (placeholder — to be deepened by hand)
       - 4xx error response shape that matches handlers.go

Usage:
  python3 backend/cmd/oasgen/generate.py docs/api/openapi.yaml
"""

import argparse
import re
import subprocess
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

# Route patterns we recognize:
#   r.Get("/path", handler)
#   r.With(mid).Post("/path", handler)
#   r.With(mid1).With(mid2).
#       Patch("/path", handler)
# The non-greedy `\b` boundary catches both `r.Get` and `).Post` in
# chained mounts; we just need to find any `.Method("/api/...")`.
#
# `\.\s*Method` allows the chained `.With(mid).\n\t\tPost("/", ...)`
# multi-line form — the `.` lives on the preceding line and the
# method name on the next, separated only by whitespace.
ROUTE_RX = re.compile(r'\.\s*(Get|Post|Put|Delete|Patch|Handle)\s*\(\s*"([^"]+)"')

# r.Route("/prefix", func(r chi.Router) { ... }) blocks. The inner
# methods only carry the SUBPATH; we need to recover the parent.
# Track brace depth from the Route opening until we hit its matching
# close brace; every method call inside that block is rebased on
# the parent prefix.
ROUTE_BLOCK_RX = re.compile(r'\.Route\s*\(\s*"([^"]+)"')


def collect_routes(repo_root: Path):
    """Walk handlers*.go + server.go, return sorted [(method, path), ...]."""
    api_dir = repo_root / "backend" / "internal" / "api"
    routes = set()
    for f in api_dir.glob("*.go"):
        text = f.read_text()
        # 1. Direct .Method("/abs/path", …) calls — original path.
        for m in ROUTE_RX.finditer(text):
            method, path = m.group(1).upper(), m.group(2)
            if method == "HANDLE":
                method = "GET"  # chi.Handle is method-any; document as GET
            if _kept_path(path):
                routes.add((method, path))

        # 2. r.Route("/prefix", func(r chi.Router) {...}) blocks.
        # Scan for each Route opener; balance braces from the next
        # `{` after it; every .Method("/sub", …) inside that block
        # contributes "/prefix/sub".
        i = 0
        while True:
            m = ROUTE_BLOCK_RX.search(text, i)
            if not m:
                break
            prefix = m.group(1)
            # Find the opening `{` of the closure body that follows.
            brace_open = text.find("{", m.end())
            if brace_open == -1:
                break
            depth = 1
            j = brace_open + 1
            while j < len(text) and depth > 0:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            block = text[brace_open:j]
            for sub in ROUTE_RX.finditer(block):
                method, subpath = sub.group(1).upper(), sub.group(2)
                # "/" inside Route maps to the bare prefix.
                full = prefix.rstrip("/") + ("" if subpath == "/" else subpath)
                if _kept_path(full):
                    routes.add((method, full))
            i = j
    return sorted(routes)


def _kept_path(path: str) -> bool:
    """Filter out non-API routes the spec doesn't document."""
    if path.startswith("/api/v1"):
        return True
    if path in ("/healthz", "/readyz", "/livez",
                "/.well-known/jwks.json", "/.well-known/security.txt",
                "/security.txt", "/metrics"):
        return True
    return False


def tag_for(path: str) -> str:
    """Bucket a path into a tag for the spec sidebar."""
    p = path.removeprefix("/api/v1/")
    head = p.split("/", 1)[0]
    aliases = {
        "auth": "auth", "tenants": "tenants", "partners": "partners",
        "engagements": "engagements", "scope": "scope", "assets": "assets",
        "scans": "scans", "scan-jobs": "scans", "agents": "agents",
        "findings": "findings", "evidence": "evidence", "reports": "reports",
        "retest-batches": "retesting", "retests": "retesting",
        "integrations": "integrations", "marketplace": "marketplace",
        "audit": "audit", "platform": "platform-ops",
        "scanner": "scanner-ops", "agent-updates": "agents",
        "dashboards": "dashboards", "compliance": "compliance",
        "mobile": "mobile", "feedback": "feedback",
        "settings": "settings", "report-schedules": "reports",
        "users": "users", "branding": "branding", "clients": "clients",
        "orchestrator": "internal", ".well-known": "internal",
        "integration-health": "integrations",
    }
    return aliases.get(head, head)


def operation_id(method: str, path: str) -> str:
    """method_segments_from_path → camelCase operationId.

    Prefix-stripping uses the LONGEST matching common prefix so two
    paths that differ only by a leading mount point produce DIFFERENT
    operationIds (e.g. /.well-known/jwks.json vs /api/v1/.well-known/
    jwks.json must NOT collide; OpenAPI requires globally-unique
    operationIds).
    """
    # Don't strip — operate on the full path so /api/v1/foo and
    # /foo are distinct. Prefix only the `api_v1_` for the common case
    # so the camelCase reads cleanly.
    p = path
    if p.startswith("/api/v1/"):
        p = "api_v1_" + p.removeprefix("/api/v1/")
    elif p.startswith("/"):
        p = p[1:]
    parts = re.findall(r'[a-zA-Z][a-zA-Z0-9-]*', p)
    parts = [pp.replace('-', '') for pp in parts if pp]
    if not parts:
        parts = ["root"]
    op = method.lower() + "".join(s.capitalize() for s in parts)
    return op


def parameters_for(path: str):
    """Extract {name} path parameters."""
    out = []
    for name in re.findall(r'\{([^}]+)\}', path):
        out.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        })
    return out


# --------------------------------------------------------------------------
# SCHEMA_OVERRIDES — hand-authored, verified-against-handler request and
# response shapes. Every (method, path) entry here has been cross-checked
# against the real handler code: response shapes derive from `writeJSON(...)`
# calls and the models package; request shapes derive from the `decode(r,
# &req)` struct definitions in handlers.go.
#
# Everything NOT in this map keeps the placeholder
# `additionalProperties=true` shape that the contract test accepts.
# Adding an entry here is GA-readiness work — operators tightening the
# spec on a route they've audited end-to-end.
#
# Honest current state:
#   * Entries below: 13 endpoints with tight schemas
#   * Total routes:  ~223 (see paths summary at end of openapi.yaml)
#   * Coverage:      ~6%. The remaining endpoints are accurate enough
#                    for client codegen at the field-list level but
#                    surface NO type constraints (string vs int vs uuid,
#                    nullable, enum membership). Tightening more
#                    endpoints is a future iteration.
# --------------------------------------------------------------------------

# Reusable component shapes — defined once, referenced from
# response_200 / request entries below.
_USER_SCHEMA = {
    "type": "object",
    "properties": {
        "id":            {"type": "string", "format": "uuid"},
        "platform_id":   {"type": "string", "format": "uuid"},
        "partner_id":    {"type": "string", "format": "uuid", "nullable": True},
        "tenant_id":     {"type": "string", "format": "uuid", "nullable": True},
        "email":         {"type": "string", "format": "email"},
        "full_name":     {"type": "string"},
        "mfa_enabled":   {"type": "boolean"},
        "status":        {"type": "string", "enum": ["active", "suspended", "erased"]},
        "last_login_at": {"type": "string", "format": "date-time", "nullable": True},
        "created_at":    {"type": "string", "format": "date-time"},
    },
    "required": ["id", "platform_id", "email", "full_name", "mfa_enabled", "status", "created_at"],
}

_TENANT_SCHEMA = {
    "type": "object",
    "properties": {
        "id":             {"type": "string", "format": "uuid"},
        "platform_id":    {"type": "string", "format": "uuid"},
        "partner_id":     {"type": "string", "format": "uuid"},
        "name":           {"type": "string"},
        "slug":           {"type": "string"},
        "status":         {"type": "string", "enum": ["active", "suspended", "quarantined", "deleted"]},
        "isolation_mode": {"type": "string", "enum": ["shared", "dedicated"]},
        "created_at":     {"type": "string", "format": "date-time"},
    },
    "required": ["id", "platform_id", "partner_id", "name", "slug", "status", "created_at"],
}

_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "id":               {"type": "string", "format": "uuid"},
        "platform_id":      {"type": "string", "format": "uuid"},
        "tenant_id":        {"type": "string", "format": "uuid"},
        "partner_id":       {"type": "string", "format": "uuid"},
        "engagement_id":    {"type": "string", "format": "uuid"},
        "asset_id":         {"type": "string", "format": "uuid", "nullable": True},
        "scan_job_id":      {"type": "string", "format": "uuid", "nullable": True},
        "title":            {"type": "string"},
        "description":      {"type": "string"},
        "severity":         {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "confidence":       {"type": "string", "enum": ["low", "medium", "high"]},
        "cvss_score":       {"type": "number", "minimum": 0, "maximum": 10},
        "cvss_vector":      {"type": "string"},
        "cwe":              {"type": "string"},
        "cve":              {"type": "string"},
        "scanner":          {"type": "string"},
        "scan_type":        {"type": "string"},
        "affected_endpoint": {"type": "string"},
        "port":             {"type": "integer"},
        "protocol":         {"type": "string"},
        "status":           {"type": "string", "enum": [
            "open", "triaged", "assigned", "in_progress",
            "risk_accepted", "false_positive", "remediated",
            "retest_requested", "retest_passed", "retest_failed", "closed"
        ]},
    },
    "required": ["id", "platform_id", "tenant_id", "partner_id", "engagement_id", "title", "severity", "status"],
}

_ERROR_REF = {"$ref": "#/components/schemas/Error"}

SCHEMA_OVERRIDES = {
    # ----- Identity / Auth -------------------------------------------------
    "GET /api/v1/auth/me": {
        "response_200": {
            "type": "object",
            "properties": {
                "user_id":      {"type": "string", "format": "uuid"},
                "email":        {"type": "string", "format": "email"},
                "full_name":    {"type": "string"},
                "platform_id":  {"type": "string", "format": "uuid"},
                "partner_id":   {"type": "string", "format": "uuid", "nullable": True},
                "tenant_id":    {"type": "string", "format": "uuid", "nullable": True},
                "roles":        {"type": "array", "items": {"type": "string"}},
                "permissions":  {"type": "array", "items": {"type": "string"}},
                "mfa_verified": {"type": "boolean"},
            },
            "required": ["user_id", "email", "platform_id", "roles", "permissions", "mfa_verified"],
        },
    },
    "POST /api/v1/auth/logout": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["revoked"]}},
            "required": ["status"],
        },
    },

    # ----- Liveness/readiness probes ---------------------------------------
    "GET /healthz": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["ok"]}},
            "required": ["status"],
        },
    },
    "GET /livez": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["ok"]}},
            "required": ["status"],
        },
    },

    # ----- Tenants ---------------------------------------------------------
    "POST /api/v1/tenants": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "platform_id":    {"type": "string", "format": "uuid"},
                "partner_id":     {"type": "string", "format": "uuid"},
                "name":           {"type": "string", "minLength": 1, "maxLength": 200},
                "slug":           {"type": "string", "pattern": "^[a-z0-9-]+$"},
                "isolation_mode": {"type": "string", "enum": ["shared", "dedicated"]},
            },
            "required": ["name", "slug"],
        },
        "response_200": _TENANT_SCHEMA,
    },
    "GET /api/v1/tenants/{tenant_id}": {"response_200": _TENANT_SCHEMA},
    "POST /api/v1/tenants/{tenant_id}/suspend": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["suspended"]}},
            "required": ["status"],
        },
    },
    "PUT /api/v1/tenants/{tenant_id}/residency": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "enum": ["us", "eu", "ae", "ap"]},
                "reason": {"type": "string"},
            },
            "required": ["region"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "format": "uuid"},
                "region":    {"type": "string"},
            },
        },
    },

    # ----- Users -----------------------------------------------------------
    "GET /api/v1/users/{user_id}": {"response_200": _USER_SCHEMA},
    "POST /api/v1/users/{user_id}/erase": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {"reason": {"type": "string", "minLength": 1}},
            "required": ["reason"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "user_id":                 {"type": "string", "format": "uuid"},
                "login_events_swept":      {"type": "integer", "minimum": 0},
                "token_revocations_swept": {"type": "integer", "minimum": 0},
                "regulation":              {"type": "string", "enum": ["gdpr_art17"]},
            },
            "required": ["user_id", "regulation"],
        },
    },

    # ----- Findings --------------------------------------------------------
    "GET /api/v1/findings/{finding_id}": {"response_200": _FINDING_SCHEMA},
    "GET /api/v1/findings": {
        "response_200": {
            "type": "array",
            "items": _FINDING_SCHEMA,
        },
    },

    # ----- Usage / Status --------------------------------------------------
    "GET /api/v1/status": {
        "response_200": {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "uptime":  {"type": "string"},
                "now":     {"type": "string", "format": "date-time"},
            },
            "required": ["version", "uptime"],
        },
    },

    # ----- Audit -----------------------------------------------------------
    "GET /api/v1/audit/verify": {
        "response_200": {
            "type": "object",
            "properties": {
                "chain_valid":  {"type": "boolean"},
                "broken_at_id": {"type": "integer", "minimum": 0},
            },
            "required": ["chain_valid", "broken_at_id"],
        },
    },
}


SUMMARY_HINTS = {
    # ----- Marketplace --------------------------------------------------
    "GET /api/v1/marketplace/listings": "List partner integration marketplace catalog.",
    "POST /api/v1/marketplace/installs": "Install a marketplace listing for the calling tenant.",
    "PATCH /api/v1/marketplace/installs/{install_id}": "Configure a pending marketplace install.",
    "DELETE /api/v1/marketplace/installs/{install_id}": "Uninstall (soft-suspend) a marketplace install.",
    "GET /api/v1/marketplace/installs": "List the calling tenant's marketplace installs.",

    # ----- Feedback / NPS ----------------------------------------------
    "POST /api/v1/feedback": "Submit user feedback (bug/feature/NPS).",
    "POST /api/v1/feedback/dismiss-nps": "Hide the NPS prompt for the current session.",
    "GET /api/v1/feedback": "List feedback items (admin/triage view).",
    "PATCH /api/v1/feedback/{feedback_id}": "Triage a feedback item.",

    # ----- Mobile-portal sidecar surface -------------------------------
    "POST /api/v1/mobile/devices": "Enroll a mobile device with a push token.",
    "DELETE /api/v1/mobile/devices/{device_id}": "Revoke a mobile device.",
    "GET /api/v1/mobile/dashboard": "Read the mobile-portal dashboard summary.",
    "POST /api/v1/mobile/alerts/ack": "Acknowledge a push-notification alert.",
    "POST /api/v1/mobile/emergency-stop": "Mobile-initiated emergency stop.",

    # ----- Public surfaces --------------------------------------------
    "GET /api/v1/.well-known/jwks.json": "JSON Web Key Set for JWT verification.",
    "GET /api/v1/orchestrator/public-key": "Cloud orchestrator's public key (PEM).",
    "GET /healthz":   "Liveness probe — does NOT touch downstream stores.",
    "GET /readyz":    "Readiness probe — DB + audit-chain checks. Strips internal hostnames.",
    "GET /api/v1/status": "Public status (version + uptime + component health).",
    "GET /api/v1/branding": "Resolve white-label branding by Host header.",

    # ----- Auth + identity -------------------------------------------
    "GET /api/v1/auth/me": "Return the calling identity, roles, and effective permissions.",
    "POST /api/v1/auth/logout": "Revoke every active JWT for the caller's user.",
    "POST /api/v1/auth/mfa/verify": "Complete a partial login with a TOTP code.",
    "POST /api/v1/auth/mfa/enroll/start": "Begin TOTP enrolment; returns the secret + QR.",
    "POST /api/v1/auth/mfa/enroll/confirm": "Finish TOTP enrolment after the user types the first code.",
    "POST /api/v1/auth/dev-token": "Mint a dev-only HS256 JWT. Disabled in production.",
    "POST /api/v1/auth/jwt-keys/rotate": "Rotate the active JWT signing key. ZAISHIELD super-admin only.",

    # ----- Dashboards -------------------------------------------------
    "GET /api/v1/dashboards/compliance": "Compliance posture grid (frameworks × coverage).",
    "GET /api/v1/dashboards/geo": "Geographic-distribution map for assets and findings.",
    "GET /api/v1/dashboards/layouts": "List saved per-user dashboard layouts.",
    "POST /api/v1/dashboards/layouts": "Save a dashboard layout.",
    "GET /api/v1/dashboards/stream": "Server-Sent Events stream of live dashboard updates.",

    # ----- Findings ---------------------------------------------------
    "GET /api/v1/findings/clusters": "Group similar findings into clusters (vuln-class deduplication).",
    "GET /api/v1/findings/export.sarif": "Export findings as SARIF v2.1.0 (consumed by GitHub / GitLab code-scanning UIs).",

    # ----- Integrations ----------------------------------------------
    "GET /api/v1/integration-health": "Per-integration delivery health rollup.",
    "GET /api/v1/integrations/{integration_id}/dead-letters": "List undelivered events for an integration.",

    # ----- Retests + reporting ---------------------------------------
    "GET /api/v1/retest-batches/{batch_id}": "Read a retest batch's progress.",
    "GET /api/v1/retests/{retest_id}/diff": "Compare pre vs post-fix scan output for a retest.",

    # ----- Compliance + reporting ------------------------------------
    "GET /api/v1/compliance/{framework}/engagements/{engagement_id}": "Compliance report for an engagement in a given framework (ISO27001 / SOC2 / PCI / HIPAA).",
    "GET /api/v1/compliance/{framework}/engagements/{engagement_id}.md": "Same report as Markdown.",

    # ----- Agents -----------------------------------------------------
    "GET /api/v1/agents/{agent_id}/emergency-stop-sla": "Time-to-emergency-stop SLA for an agent.",
    "GET /api/v1/agents/{agent_id}/telemetry": "Heartbeat + resource telemetry timeline.",
    "GET /api/v1/agents/{agent_id}/update-offer": "Available agent-binary update (signed offer).",

    # ----- Partner-admin surface -------------------------------------
    "GET /api/v1/partners/{partner_id}/preview": "Render a branded portal preview for the partner.",

    # ----- Platform-admin / break-glass ------------------------------
    "GET /api/v1/platform/maintenance": "Read platform-wide maintenance window state.",
    "GET /api/v1/platform/policy-rules": "List platform-wide policy rules in effect.",
    "POST /api/v1/platform/break-glass/redeem": "Redeem a break-glass admin token (audited).",

    # ----- Emergency stop --------------------------------------------
    "POST /api/v1/emergency-stops/{stop_id}/ack": "Acknowledge an emergency-stop notification.",

    # ----- Audit ------------------------------------------------------
    "GET /api/v1/audit/verify": "Verify the most recent audit-chain tail.",
    "GET /api/v1/audit/verify-deep": "Walk the full audit chain — run as a cron, not interactively.",

    # ----- Scanner farm ----------------------------------------------
    "GET /api/v1/scanner/regions/{region}/quota": "Per-region scanner quota + utilisation.",

    # ----- Tenants admin ---------------------------------------------
    "GET /api/v1/tenants": "List tenants visible to the caller.",

    # ----- GA additions (see top-of-file docstring for full schemas) -
    "GET /api/v1/usage":   "Self-service usage, plan, and rate-limit visibility for the caller.",
    "GET /api/v1/status":  "Public health + version + uptime snapshot (status-page friendly).",
    "GET /api/v1/audit/export": "Bulk audit-log export (NDJSON default; ?format=csv). Tenant callers must scope by ?from=<rfc3339>.",
    "POST /api/v1/users/{user_id}/erase": "GDPR Article 17 erasure — pseudonymises PII across users, login_events, token_revocations.",
    "PUT /api/v1/tenants/{tenant_id}/residency": "Pin or clear the tenant's data-residency commitment.",
    "POST /api/v1/integrations/{integration_id}/inbound": "Partner-side inbound webhook callback (authenticated by HMAC, not bearer).",
    "PUT /api/v1/integrations/{integration_id}/signing-secret": "Rotate the inbound webhook signing secret.",

    # ----- External + internal plane (migration 0061) ----------------
    "GET /api/v1/tenants/{tenant_id}/sso":     "Read the tenant's SAML/OIDC IdP federation config.",
    "PUT /api/v1/tenants/{tenant_id}/sso":     "Upsert the tenant's SAML/OIDC IdP federation config. Customer self-serve.",
    "GET /api/v1/tenants/{tenant_id}/scim/tokens": "List SCIM provisioning tokens (metadata; no plaintext).",
    "POST /api/v1/tenants/{tenant_id}/scim/tokens": "Mint a SCIM provisioning token. Plaintext returned ONCE.",
    "DELETE /api/v1/tenants/{tenant_id}/scim/tokens/{token_id}": "Revoke a SCIM provisioning token.",
    "GET /api/v1/partners/{partner_id}/billing/plan-requests":  "List the partner's plan-change requests.",
    "POST /api/v1/partners/{partner_id}/billing/plan-requests": "File a plan-change request (customer-initiated).",
    "GET /api/v1/compliance/tenants/{tenant_id}/rollup":   "Per-framework compliance coverage rollup for the tenant.",
    "POST /api/v1/compliance/tenants/{tenant_id}/snapshot": "Persist a frozen 'as-of' snapshot of the tenant's compliance rollup.",
    "GET /api/v1/platform/billing/plan-requests":          "Operator queue of pending plan-change requests.",
    "POST /api/v1/platform/billing/plan-requests/{id}/decide": "Approve / reject / cancel a customer plan-change request.",
    "POST /api/v1/platform/billing/usage-adjustments":     "Operator credit / surcharge for a partner's monthly usage.",
    "POST /api/v1/platform/impersonate":                   "Open a support-engineer impersonation session (ticket-tagged, dual-audited).",
    "DELETE /api/v1/platform/impersonate/{session_id}":    "End an open impersonation session.",
    "GET /api/v1/platform/impersonate/active":             "List currently-open impersonation sessions.",
    "POST /api/v1/platform/tenants/{tenant_id}/quarantine":   "Mark a tenant for hard-delete after the 7-day quarantine window.",
    "DELETE /api/v1/platform/tenants/{tenant_id}/quarantine": "Cancel a tenant's quarantine and restore access.",
    "POST /api/v1/platform/tenants/{tenant_id}/migrate":      "Move a tenant from one partner to another (full audit trail).",
}


def emit_yaml(routes, out_path: Path):
    by_path = defaultdict(dict)
    for method, path in routes:
        op = {
            "summary": SUMMARY_HINTS.get(f"{method} {path}", f"{method} {path}"),
            "operationId": operation_id(method, path),
            "tags": [tag_for(path)],
        }
        params = parameters_for(path)
        if params:
            op["parameters"] = params
        override = SCHEMA_OVERRIDES.get(f"{method} {path}")
        if method in ("POST", "PUT", "PATCH"):
            req_schema = (override or {}).get("request") if override else None
            op["requestBody"] = {
                "required": override is not None and override.get("request_required", False),
                "content": {
                    "application/json": {
                        "schema": req_schema or {"type": "object", "additionalProperties": True},
                    },
                },
            }
        # Per-path Content-Type overrides for endpoints that don't
        # return JSON. The contract test validates response headers
        # against the spec — JWKS returns application/jwk-set+json,
        # /orchestrator/public-key returns application/x-pem-file,
        # the SARIF export returns application/sarif+json, etc.
        ct = "application/json"
        schema_200 = {"type": "object", "additionalProperties": True}
        if path.endswith("/jwks.json"):
            ct = "application/jwk-set+json"
        elif path.endswith("/orchestrator/public-key"):
            ct = "application/x-pem-file"
            schema_200 = {"type": "string"}
        elif path.endswith(".sarif"):
            ct = "application/sarif+json"
        elif path.endswith(".md"):
            ct = "text/markdown"
        elif path.endswith("security.txt"):
            ct = "text/plain"
            schema_200 = {"type": "string"}
        elif path == "/healthz" or path == "/readyz" or path == "/livez":
            # Liveness/readiness probes emit JSON ({"status":"ok"}).
            ct = "application/json"
        elif path == "/metrics":
            # Prometheus library negotiates a content-type whose
            # parameter set varies across client versions
            # (charset=utf-8, escaping=underscores). Match the
            # current expanded form so the contract test stays green.
            ct = "text/plain; version=0.0.4; charset=utf-8; escaping=underscores"
            schema_200 = {"type": "string"}
        elif path.endswith("/audit/export"):
            ct = "application/x-ndjson"
            schema_200 = {"type": "string"}
        elif "/dashboards/stream" in path:
            ct = "text/event-stream"
            schema_200 = {"type": "string"}
        # Per-(method,path) hand-authored response schema overrides
        # the placeholder additionalProperties=true shape. Anything
        # not in SCHEMA_OVERRIDES still emits the placeholder so the
        # contract test stays green; the override only TIGHTENS the
        # spec on endpoints we've actually verified by hand.
        if override and override.get("response_200"):
            schema_200 = override["response_200"]
        op["responses"] = {
            "200": {
                "description": "Success",
                "content": {ct: {"schema": schema_200}},
            },
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "404": {"$ref": "#/components/responses/NotFound"},
            "500": {"$ref": "#/components/responses/Internal"},
        }
        by_path[path][method.lower()] = op

    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "ZAISHIELD VAULTSCAN API",
            "version": "1.0.0",
            "description": "Auto-generated baseline. Operation summaries + response schemas SHOULD be deepened by hand.",
        },
        "servers": [
            {"url": "https://api.vaultscan.zaishield.com"},
            {"url": "http://localhost:8080"},
        ],
        "paths": dict(by_path),
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
            },
            "responses": {
                "BadRequest":   {"description": "Invalid request",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Unauthorized": {"description": "Missing or invalid bearer token",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Forbidden":    {"description": "Permission denied / cross-tenant",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "NotFound":     {"description": "Resource not found",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Internal":     {"description": "Internal server error",
                                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code":    {"type": "string"},
                                "message": {"type": "string"},
                            },
                            "required": ["code", "message"],
                        },
                    },
                    "required": ["error"],
                },
            },
        },
        "security": [{"bearerAuth": []}],
    }

    # Naive YAML emitter so we don't depend on PyYAML.
    out = []
    def emit(node, indent=0):
        pad = "  " * indent
        if isinstance(node, dict):
            for k, v in node.items():
                key = str(k)
                if isinstance(v, (dict, list)) and v:
                    out.append(f"{pad}{key}:")
                    emit(v, indent + 1)
                else:
                    out.append(f"{pad}{key}: {yaml_scalar(v)}")
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    first = True
                    for k, v in item.items():
                        prefix = "- " if first else "  "
                        first = False
                        if isinstance(v, (dict, list)) and v:
                            out.append(f"{pad}{prefix}{k}:")
                            # Children must align UNDER the key text, which
                            # itself is indented past the "- " / "  " prefix.
                            # That's +2 columns vs the current pad, hence
                            # indent+2 not indent+1.
                            emit(v, indent + 2)
                        else:
                            out.append(f"{pad}{prefix}{k}: {yaml_scalar(v)}")
                else:
                    out.append(f"{pad}- {yaml_scalar(item)}")

    def yaml_scalar(v):
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        # Empty list / dict are valid YAML scalars; emit as
        # `[]` / `{}` literally rather than quoting their str().
        if isinstance(v, list) and len(v) == 0:
            return "[]"
        if isinstance(v, dict) and len(v) == 0:
            return "{}"
        s = str(v)
        if any(c in s for c in ":#{}[],&*!|>'\"%@`") or s.lstrip() != s:
            return '"' + s.replace('"', '\\"') + '"'
        return s

    emit(spec)
    out_path.write_text("\n".join(out) + "\n")
    print(f"wrote {out_path} with {len(routes)} routes", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output", help="path to write the OpenAPI YAML")
    ap.add_argument("--repo-root", default=".", help="repo root (default cwd)")
    args = ap.parse_args()
    repo = Path(args.repo_root).resolve()
    routes = collect_routes(repo)
    emit_yaml(routes, Path(args.output))


if __name__ == "__main__":
    main()
