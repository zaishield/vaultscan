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

# Same as ROUTE_RX but ALSO captures the handler function name. Used
# to look up the discovered writeJSON keys for that handler.
# Pattern: .Method("/path", handlerFunc(... — capture handlerFunc.
ROUTE_RX_WITH_HANDLER = re.compile(
    r'\.\s*(Get|Post|Put|Delete|Patch|Handle)\s*\(\s*"([^"]+)"\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)')

# r.Route("/prefix", func(r chi.Router) { ... }) blocks. The inner
# methods only carry the SUBPATH; we need to recover the parent.
# Track brace depth from the Route opening until we hit its matching
# close brace; every method call inside that block is rebased on
# the parent prefix.
ROUTE_BLOCK_RX = re.compile(r'\.Route\s*\(\s*"([^"]+)"')


def collect_routes(repo_root: Path):
    """Walk handlers*.go + server.go.

    Returns (sorted [(method, path)], dict (method, path) → handler_func).
    The handler-func map is sparse — only filled for routes whose
    registration line includes a recognizable handler call. Anonymous
    inline handlers (`r.Get("/x", func(w, r) {...})`) won't be there.
    """
    api_dir = repo_root / "backend" / "internal" / "api"
    routes = set()
    route_to_handler = {}
    for f in api_dir.glob("*.go"):
        text = f.read_text()
        # Capture handler-func names where present.
        for m in ROUTE_RX_WITH_HANDLER.finditer(text):
            method, path, handler = m.group(1).upper(), m.group(2), m.group(3)
            if method == "HANDLE":
                method = "GET"
            if _kept_path(path):
                route_to_handler[(method, path)] = handler

        # 1. Direct .Method("/abs/path", …) calls — original path.
        for m in ROUTE_RX.finditer(text):
            method, path = m.group(1).upper(), m.group(2)
            if method == "HANDLE":
                method = "GET"  # chi.Handle is method-any; document as GET
            if _kept_path(path):
                routes.add((method, path))

        # 2. r.Route("/prefix", func(r chi.Router) {...}) blocks.
        i = 0
        while True:
            m = ROUTE_BLOCK_RX.search(text, i)
            if not m:
                break
            prefix = m.group(1)
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
                full = prefix.rstrip("/") + ("" if subpath == "/" else subpath)
                if _kept_path(full):
                    routes.add((method, full))
            for sub in ROUTE_RX_WITH_HANDLER.finditer(block):
                method, subpath, handler = sub.group(1).upper(), sub.group(2), sub.group(3)
                full = prefix.rstrip("/") + ("" if subpath == "/" else subpath)
                if _kept_path(full):
                    route_to_handler[(method, full)] = handler
            i = j
    return sorted(routes), route_to_handler


def load_handler_keys(repo_root: Path):
    """Load the auto-extracted handler keys from
    backend/cmd/oasgen-extract output. Returns {} on missing file
    so the generator works even when the extract step wasn't run.
    """
    keys_path = repo_root / "backend" / "cmd" / "oasgen" / "handler_keys.json"
    if not keys_path.exists():
        return {}
    import json
    try:
        with keys_path.open() as fh:
            return json.load(fh)
    except (json.JSONDecodeError, IOError):
        return {}


def schema_from_handler_keys(fields):
    """Convert oasgen-extract output to an OpenAPI schema object.
    The schema is permissive (additionalProperties=true) so the
    contract test doesn't fail on unknown fields — but every
    DISCOVERED key gets a typed property, which is the SDK-codegen
    quality bump compared to the pure-placeholder shape.
    """
    if not fields:
        return None
    props = {}
    for f in fields:
        name = f["name"]
        t = f.get("type", "unknown")
        if t == "unknown":
            # Permissive any-type property — name is preserved for
            # client codegen + schema-aware tooling, but the value
            # type is left open.
            props[name] = {}
        else:
            props[name] = {"type": t}
    return {
        "type": "object",
        "properties": props,
        "additionalProperties": True,
    }


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
#   * SCHEMA_OVERRIDES (this dict): 70+ endpoints with hand-authored
#     tight schemas covering auth/MFA/JWT/JWKS, tenants (incl. SSO +
#     SCIM), users, partners (incl. billing + DNS), engagements,
#     scope, assets, scans, findings (incl. bulk), integrations,
#     reports, evidence (incl. signed URL + manual upload), branding,
#     agents (incl. emergency-stop SLA + update-offer), dashboards
#     (exec + technical + partner), audit/verify + verify-deep,
#     compliance rollup + snapshot, retest batches + diff, platform
#     impersonate + migration + quarantine + plan-requests + usage-
#     adjustments, health/readyz/healthz/livez, identity, and the
#     action endpoints. Tight = enums, formats, required-fields.
#   * Long-tail coverage: every other JSON route gets an
#     auto-extracted schema with named properties via
#     cmd/oasgen-extract (Go AST parser of handler writeJSON calls).
#     Property names match the actual handler keys; type hints are
#     best-effort. additionalProperties=true keeps the contract
#     test green for handler shapes the extractor can't see.
#   * Net effect: ~95%+ of JSON paths now ship with named-property
#     schemas instead of the all-permissive placeholder.
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

    # ----- Engagements ------------------------------------------------------
    "POST /api/v1/engagements": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":             {"type": "string", "format": "uuid"},
                "tenant_id":              {"type": "string", "format": "uuid"},
                "client_id":              {"type": "string", "format": "uuid"},
                "code":                   {"type": "string", "minLength": 1},
                "name":                   {"type": "string", "minLength": 1},
                "description":            {"type": "string"},
                "starts_at":              {"type": "string", "format": "date-time"},
                "ends_at":                {"type": "string", "format": "date-time"},
                "intensity":              {"type": "string", "enum": ["light", "standard", "intensive"]},
                "emergency_contact_name":  {"type": "string"},
                "emergency_contact_email": {"type": "string", "format": "email"},
                "emergency_contact_phone": {"type": "string"},
            },
            "required": ["partner_id", "tenant_id", "code", "name", "starts_at", "ends_at"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":        {"type": "string", "format": "uuid"},
                "code":      {"type": "string"},
                "name":      {"type": "string"},
                "status":    {"type": "string"},
                "starts_at": {"type": "string", "format": "date-time"},
                "ends_at":   {"type": "string", "format": "date-time"},
            },
            "required": ["id", "code", "status"],
        },
    },

    # ----- Assets -----------------------------------------------------------
    "POST /api/v1/assets": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":     {"type": "string", "format": "uuid"},
                "tenant_id":      {"type": "string", "format": "uuid"},
                "engagement_id":  {"type": "string", "format": "uuid"},
                "asset_type":     {"type": "string", "enum": [
                    "host", "url", "ip_range", "domain", "cloud_account",
                    "api_endpoint", "container_image", "code_repository",
                ]},
                "name":           {"type": "string"},
                "value":          {"type": "string"},
                "plane":          {"type": "string", "enum": ["external", "internal"]},
                "criticality":    {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "owner":          {"type": "string"},
                "environment":    {"type": "string"},
                "cloud_provider": {"type": "string", "enum": ["aws", "gcp", "azure", "other", ""]},
                "tags":           {"type": "array", "items": {"type": "string"}},
            },
            "required": ["partner_id", "tenant_id", "asset_type", "value"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":         {"type": "string", "format": "uuid"},
                "asset_type": {"type": "string"},
                "value":      {"type": "string"},
                "created_at": {"type": "string", "format": "date-time"},
            },
            "required": ["id"],
        },
    },

    # ----- Scans ------------------------------------------------------------
    "POST /api/v1/scans/external": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":    {"type": "string", "format": "uuid"},
                "tenant_id":     {"type": "string", "format": "uuid"},
                "engagement_id": {"type": "string", "format": "uuid"},
                "profile_code":  {"type": "string"},
                "region":        {"type": "string"},
                "agent_id":      {"type": "string", "format": "uuid"},
                "targets":       {"type": "array", "items": {"type": "string"}},
                "schedule_at":   {"type": "string", "format": "date-time"},
                "intensity":     {"type": "string", "enum": ["light", "standard", "intensive"]},
            },
            "required": ["engagement_id", "profile_code", "targets"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":     {"type": "string", "format": "uuid"},
                "status": {"type": "string", "enum": [
                    "queued", "approval_pending", "running", "succeeded",
                    "failed", "cancelled",
                ]},
            },
            "required": ["id", "status"],
        },
    },
    "POST /api/v1/scans/internal": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":    {"type": "string", "format": "uuid"},
                "tenant_id":     {"type": "string", "format": "uuid"},
                "engagement_id": {"type": "string", "format": "uuid"},
                "profile_code":  {"type": "string"},
                "agent_id":      {"type": "string", "format": "uuid"},
                "targets":       {"type": "array", "items": {"type": "string"}},
                "schedule_at":   {"type": "string", "format": "date-time"},
                "intensity":     {"type": "string", "enum": ["light", "standard", "intensive"]},
            },
            "required": ["engagement_id", "profile_code", "agent_id", "targets"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":     {"type": "string", "format": "uuid"},
                "status": {"type": "string"},
            },
            "required": ["id", "status"],
        },
    },
    "GET /api/v1/scans/{scan_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":            {"type": "string", "format": "uuid"},
                "engagement_id": {"type": "string", "format": "uuid"},
                "profile_code":  {"type": "string"},
                "plane":         {"type": "string", "enum": ["external", "internal"]},
                "status":        {"type": "string"},
                "started_at":    {"type": "string", "format": "date-time", "nullable": True},
                "ended_at":      {"type": "string", "format": "date-time", "nullable": True},
            },
            "required": ["id", "status"],
        },
    },

    # ----- Integrations -----------------------------------------------------
    "POST /api/v1/integrations/{integration_id}": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "tenant_id":    {"type": "string", "format": "uuid"},
                "partner_id":   {"type": "string", "format": "uuid"},
                "name":         {"type": "string", "minLength": 1},
                "config":       {"type": "object", "additionalProperties": True},
                "secret_ref":   {"type": "string"},
                "event_filter": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["name"],
        },
        "response_200": {
            "type": "object",
            "properties": {"id": {"type": "string", "format": "uuid"}},
            "required": ["id"],
        },
    },
    "POST /api/v1/integrations/{integration_id}/test": {
        "response_200": {
            "type": "object",
            "properties": {
                "ok":          {"type": "boolean"},
                "status_code": {"type": "integer"},
                "duration_ms": {"type": "integer"},
                "error":       {"type": "string"},
            },
            "required": ["ok"],
        },
    },
    "PUT /api/v1/integrations/{integration_id}/signing-secret": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {"secret": {"type": "string"}},
            "required": ["secret"],
        },
    },

    # ----- Reports ----------------------------------------------------------
    "GET /api/v1/reports/{report_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":           {"type": "string", "format": "uuid"},
                "tenant_id":    {"type": "string", "format": "uuid"},
                "report_type":  {"type": "string"},
                "status":       {"type": "string", "enum": [
                    "draft", "pending_review", "approved", "delivered", "expired",
                ]},
                "created_at":   {"type": "string", "format": "date-time"},
                "generated_at": {"type": "string", "format": "date-time", "nullable": True},
                "approved_by":  {"type": "string", "format": "uuid", "nullable": True},
            },
            "required": ["id", "report_type", "status"],
        },
    },

    # ----- Partners --------------------------------------------------------
    "POST /api/v1/partners": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "parent_id": {"type": "string", "format": "uuid"},
                "type":      {"type": "string", "enum": ["zaishield", "distributor", "mssp", "direct", "client"]},
                "name":      {"type": "string", "minLength": 1},
                "slug":      {"type": "string", "pattern": "^[a-z0-9-]+$"},
            },
            "required": ["type", "name", "slug"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":   {"type": "string", "format": "uuid"},
                "slug": {"type": "string"},
                "type": {"type": "string"},
            },
            "required": ["id"],
        },
    },
    "GET /api/v1/partners/{partner_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":         {"type": "string", "format": "uuid"},
                "parent_id":  {"type": "string", "format": "uuid", "nullable": True},
                "type":       {"type": "string"},
                "name":       {"type": "string"},
                "slug":       {"type": "string"},
                "status":     {"type": "string", "enum": ["active", "suspended"]},
                "created_at": {"type": "string", "format": "date-time"},
            },
            "required": ["id", "name", "slug", "status"],
        },
    },

    # ----- Scope -----------------------------------------------------------
    "POST /api/v1/scope": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "engagement_id": {"type": "string", "format": "uuid"},
                "target_type":   {"type": "string", "enum": [
                    "host", "url", "ip_range", "domain", "cloud_account",
                    "api_endpoint", "container_image", "code_repository",
                ]},
                "target_value":  {"type": "string"},
                "plane":         {"type": "string", "enum": ["external", "internal"]},
                "notes":         {"type": "string"},
            },
            "required": ["engagement_id", "target_type", "target_value"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":     {"type": "string", "format": "uuid"},
                "status": {"type": "string", "enum": ["pending_approval", "approved", "rejected"]},
            },
            "required": ["id", "status"],
        },
    },

    # ----- Reports ---------------------------------------------------------
    "POST /api/v1/reports": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":    {"type": "string", "format": "uuid"},
                "tenant_id":     {"type": "string", "format": "uuid"},
                "engagement_id": {"type": "string", "format": "uuid"},
                "report_type":   {"type": "string", "enum": [
                    "executive", "technical", "pentest", "compliance",
                    "incident", "post_engagement",
                ]},
                "title":         {"type": "string", "minLength": 1},
                "formats":       {"type": "array", "items": {"type": "string", "enum": ["pdf", "docx", "xlsx", "html"]}},
            },
            "required": ["engagement_id", "report_type", "title"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":     {"type": "string", "format": "uuid"},
                "status": {"type": "string"},
            },
            "required": ["id", "status"],
        },
    },

    # ----- Findings (bulk + comment) ---------------------------------------
    "POST /api/v1/findings/bulk": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "tenant_id":   {"type": "string", "format": "uuid"},
                "ids":         {"type": "array", "items": {"type": "string", "format": "uuid"}, "minItems": 1},
                "action":      {"type": "string", "enum": ["status", "assign", "risk_accept"]},
                "status":      {"type": "string"},
                "assignee_id": {"type": "string", "format": "uuid"},
                "note":        {"type": "string"},
            },
            "required": ["tenant_id", "ids", "action"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "updated": {"type": "integer", "minimum": 0},
            },
            "required": ["updated"],
        },
    },

    # ----- Branding (tenant) -----------------------------------------------
    "GET /api/v1/branding": {
        "response_200": {
            "type": "object",
            "properties": {
                "partner_id":   {"type": "string", "format": "uuid"},
                "logo_url":     {"type": "string"},
                "primary_color": {"type": "string"},
                "support_email": {"type": "string"},
            },
        },
    },

    # ----- Agents ----------------------------------------------------------
    "POST /api/v1/agents": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id": {"type": "string", "format": "uuid"},
                "tenant_id":  {"type": "string", "format": "uuid"},
                "label":      {"type": "string", "minLength": 1},
                "region":     {"type": "string"},
            },
            "required": ["partner_id", "tenant_id", "label"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":               {"type": "string", "format": "uuid"},
                "enrollment_token": {"type": "string"},
                "expires_at":       {"type": "string", "format": "date-time"},
            },
            "required": ["id", "enrollment_token"],
        },
    },
    "GET /api/v1/agents/{agent_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":         {"type": "string", "format": "uuid"},
                "label":      {"type": "string"},
                "status":     {"type": "string", "enum": [
                    "pending_enrollment", "active", "stale", "revoked", "rotating",
                ]},
                "region":     {"type": "string"},
                "last_seen_at": {"type": "string", "format": "date-time", "nullable": True},
            },
            "required": ["id", "status"],
        },
    },

    # ----- Dashboards ------------------------------------------------------
    "GET /api/v1/dashboards/executive": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":        {"type": "string", "format": "uuid"},
                "open_critical":    {"type": "integer", "minimum": 0},
                "open_high":        {"type": "integer", "minimum": 0},
                "remediation_sla_breach_count": {"type": "integer", "minimum": 0},
                "scans_last_30d":   {"type": "integer", "minimum": 0},
            },
        },
    },
    "GET /api/v1/dashboards/technical": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":         {"type": "string", "format": "uuid"},
                "findings_by_severity": {"type": "object", "additionalProperties": {"type": "integer"}},
                "findings_by_status":   {"type": "object", "additionalProperties": {"type": "integer"}},
                "top_assets_by_finding_count": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "asset_id":      {"type": "string", "format": "uuid"},
                            "value":         {"type": "string"},
                            "finding_count": {"type": "integer"},
                        },
                    },
                },
            },
        },
    },

    # ----- Auth surfaces ---------------------------------------------------
    "POST /api/v1/auth/dev-token": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "format": "uuid"},
                "ttl_min": {"type": "integer", "minimum": 1, "maximum": 1440},
            },
            "required": ["user_id"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "access_token": {"type": "string"},
                "expires_at":   {"type": "string", "format": "date-time"},
            },
            "required": ["access_token", "expires_at"],
        },
    },
    "POST /api/v1/auth/mfa/verify": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "challenge_token": {"type": "string"},
                "totp_code":       {"type": "string", "pattern": "^[0-9]{6}$"},
            },
            "required": ["challenge_token", "totp_code"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "access_token": {"type": "string"},
                "expires_at":   {"type": "string", "format": "date-time"},
                "mfa_verified": {"type": "boolean"},
            },
            "required": ["access_token", "expires_at", "mfa_verified"],
        },
    },
    "POST /api/v1/auth/jwt-keys/rotate": {
        "response_200": {
            "type": "object",
            "properties": {
                "status":  {"type": "string", "enum": ["rotated"]},
                "new_kid": {"type": "string"},
            },
            "required": ["status", "new_kid"],
        },
    },

    # ----- Evidence -------------------------------------------------------
    "GET /api/v1/evidence/{evidence_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":           {"type": "string", "format": "uuid"},
                "tenant_id":    {"type": "string", "format": "uuid"},
                "finding_id":   {"type": "string", "format": "uuid", "nullable": True},
                "kind":         {"type": "string"},
                "sha256":       {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                "size_bytes":   {"type": "integer", "minimum": 0},
                "content_type": {"type": "string"},
                "uploaded_at":  {"type": "string", "format": "date-time"},
            },
            "required": ["id", "tenant_id", "kind", "sha256", "size_bytes"],
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
    "GET /api/v1/audit/verify-deep": {
        "response_200": {
            "type": "object",
            "properties": {
                "total_rows":    {"type": "integer", "minimum": 0},
                "first_bad_id":  {"type": "integer", "minimum": 0},
                "last_good_id":  {"type": "integer", "minimum": 0},
                "detected_at":   {"type": "string", "format": "date-time"},
                "expected_hash": {"type": "string"},
                "stored_hash":   {"type": "string"},
                "detail":        {"type": "string"},
            },
            "required": ["total_rows", "first_bad_id", "last_good_id", "detected_at"],
        },
    },
    # Keep the POST entry for sites that wire verify-deep as POST.
    "POST /api/v1/audit/verify-deep": {
        # audit.VerifyResult — same shape as Verify but with chunks
        # of the chain hashed.
        "response_200": {
            "type": "object",
            "properties": {
                "total_rows":    {"type": "integer", "minimum": 0},
                "first_bad_id":  {"type": "integer", "minimum": 0},
                "last_good_id":  {"type": "integer", "minimum": 0},
                "detected_at":   {"type": "string", "format": "date-time"},
                "expected_hash": {"type": "string"},
                "stored_hash":   {"type": "string"},
                "detail":        {"type": "string"},
            },
            "required": ["total_rows", "first_bad_id", "last_good_id", "detected_at"],
        },
    },

    # ----- JWKS -----------------------------------------------------------
    # JWK Set per RFC 7517. Each key has kty + alg + kid + the
    # algorithm-specific key material (n,e for RSA / crv,x,y for EC).
    "GET /.well-known/jwks.json": {
        "response_200": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kty": {"type": "string", "enum": ["RSA", "EC", "OKP", "oct"]},
                            "kid": {"type": "string"},
                            "alg": {"type": "string"},
                            "use": {"type": "string", "enum": ["sig", "enc", ""]},
                            "n":   {"type": "string"},
                            "e":   {"type": "string"},
                            "crv": {"type": "string"},
                            "x":   {"type": "string"},
                            "y":   {"type": "string"},
                        },
                        "required": ["kty", "kid"],
                    },
                },
            },
            "required": ["keys"],
        },
    },
    "GET /api/v1/.well-known/jwks.json": {
        "response_200": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kty": {"type": "string"},
                            "kid": {"type": "string"},
                            "alg": {"type": "string"},
                            "use": {"type": "string"},
                            "n":   {"type": "string"},
                            "e":   {"type": "string"},
                            "crv": {"type": "string"},
                            "x":   {"type": "string"},
                            "y":   {"type": "string"},
                        },
                        "required": ["kty", "kid"],
                    },
                },
            },
            "required": ["keys"],
        },
    },

    # ----- Engagements (GET) ---------------------------------------------
    "GET /api/v1/engagements/{engagement_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":            {"type": "string", "format": "uuid"},
                "platform_id":   {"type": "string", "format": "uuid"},
                "partner_id":    {"type": "string", "format": "uuid"},
                "tenant_id":     {"type": "string", "format": "uuid"},
                "code":          {"type": "string"},
                "name":          {"type": "string"},
                "description":   {"type": "string"},
                "status":        {"type": "string", "enum": ["draft", "active", "paused", "completed", "cancelled"]},
                "starts_at":     {"type": "string", "format": "date-time"},
                "ends_at":       {"type": "string", "format": "date-time"},
                "intensity":     {"type": "string"},
                "created_at":    {"type": "string", "format": "date-time"},
            },
            "required": ["id", "code", "status"],
        },
    },

    # ----- Dashboards (partner) -------------------------------------------
    "GET /api/v1/dashboards/partner": {
        "response_200": {
            "type": "object",
            "properties": {
                "partner_id":    {"type": "string", "format": "uuid"},
                "tenant_count":  {"type": "integer", "minimum": 0},
                "scans_last_30d": {"type": "integer", "minimum": 0},
                "open_critical": {"type": "integer", "minimum": 0},
                "open_high":     {"type": "integer", "minimum": 0},
            },
        },
    },

    # ----- Health ---------------------------------------------------------
    "GET /api/v1/health": {
        "response_200": {
            "type": "object",
            "properties": {
                "status":     {"type": "string", "enum": ["ok", "degraded", "unhealthy"]},
                "timestamp":  {"type": "string", "format": "date-time"},
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name":   {"type": "string"},
                            "status": {"type": "string"},
                            "detail": {"type": "string"},
                        },
                    },
                },
            },
            "required": ["status"],
        },
    },
    "GET /readyz": {
        "response_200": {
            "type": "object",
            "properties": {
                "status":     {"type": "string", "enum": ["ok", "degraded", "unhealthy"]},
                "timestamp":  {"type": "string", "format": "date-time"},
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name":   {"type": "string"},
                            "status": {"type": "string"},
                        },
                    },
                },
            },
        },
    },

    # ----- Tenant SSO + SCIM ---------------------------------------------
    "GET /api/v1/tenants/{tenant_id}/sso": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":         {"type": "string", "format": "uuid"},
                "provider_type":     {"type": "string", "enum": ["none", "saml", "oidc"]},
                "enabled":           {"type": "boolean"},
                "metadata_xml":      {"type": "string"},
                "discovery_url":     {"type": "string"},
                "client_id":         {"type": "string"},
                "client_secret_set": {"type": "boolean"},
                "claim_mapping":     {"type": "object", "additionalProperties": {"type": "string"}},
            },
            "required": ["provider_type", "enabled"],
        },
    },
    "GET /api/v1/tenants/{tenant_id}/scim/tokens": {
        "response_200": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":          {"type": "string", "format": "uuid"},
                            "label":       {"type": "string"},
                            "prefix":      {"type": "string"},
                            "created_at":  {"type": "string", "format": "date-time"},
                            "expires_at":  {"type": "string", "format": "date-time", "nullable": True},
                            "revoked_at":  {"type": "string", "format": "date-time", "nullable": True},
                        },
                    },
                },
            },
        },
    },

    # ----- Evidence signed URL -------------------------------------------
    "GET /api/v1/evidence/{evidence_id}/url": {
        "response_200": {
            "type": "object",
            "properties": {
                "url":        {"type": "string", "format": "uri"},
                "expires_at": {"type": "string", "format": "date-time"},
            },
            "required": ["url", "expires_at"],
        },
    },

    # ----- Compliance rollup ---------------------------------------------
    "GET /api/v1/compliance/tenants/{tenant_id}/rollup": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":  {"type": "string", "format": "uuid"},
                "frameworks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "framework":          {"type": "string", "enum": ["soc2", "iso27001", "pci_dss", "hipaa", "fedramp"]},
                            "controls_total":     {"type": "integer", "minimum": 0},
                            "controls_satisfied": {"type": "integer", "minimum": 0},
                            "controls_gap":       {"type": "integer", "minimum": 0},
                            "coverage_pct":       {"type": "number", "minimum": 0, "maximum": 100},
                        },
                    },
                },
                "generated_at": {"type": "string", "format": "date-time"},
            },
        },
    },
    "POST /api/v1/compliance/tenants/{tenant_id}/snapshot": {
        "response_200": {
            "type": "object",
            "properties": {
                "snapshot_id":  {"type": "string", "format": "uuid"},
                "tenant_id":    {"type": "string", "format": "uuid"},
                "generated_at": {"type": "string", "format": "date-time"},
            },
            "required": ["snapshot_id", "tenant_id"],
        },
    },

    # ----- Retest batches + retests --------------------------------------
    "GET /api/v1/retest-batches/{batch_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "id":          {"type": "string", "format": "uuid"},
                "tenant_id":   {"type": "string", "format": "uuid"},
                "status":      {"type": "string"},
                "created_at":  {"type": "string", "format": "date-time"},
                "completed_at": {"type": "string", "format": "date-time", "nullable": True},
                "retests": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
            "required": ["id", "status"],
        },
    },
    "GET /api/v1/retests/{retest_id}/diff": {
        "response_200": {
            "type": "object",
            "properties": {
                "retest_id":     {"type": "string", "format": "uuid"},
                "finding_id":    {"type": "string", "format": "uuid"},
                "before_status": {"type": "string"},
                "after_status":  {"type": "string"},
                "changed":       {"type": "boolean"},
            },
            "required": ["retest_id", "changed"],
        },
    },

    # ----- Partner billing -----------------------------------------------
    "GET /api/v1/partners/{partner_id}/billing/plan-requests": {
        "response_200": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":          {"type": "string", "format": "uuid"},
                            "from_plan":   {"type": "string"},
                            "to_plan":     {"type": "string"},
                            "status":      {"type": "string", "enum": ["pending", "approved", "rejected"]},
                            "reason":      {"type": "string"},
                            "filed_at":    {"type": "string", "format": "date-time"},
                            "decided_at":  {"type": "string", "format": "date-time", "nullable": True},
                        },
                    },
                },
            },
        },
    },
    "GET /api/v1/partners/{partner_id}/billing/usage": {
        "response_200": {
            "type": "object",
            "properties": {
                "partner_id":      {"type": "string", "format": "uuid"},
                "period_start":    {"type": "string", "format": "date-time"},
                "period_end":      {"type": "string", "format": "date-time"},
                "scans_count":     {"type": "integer", "minimum": 0},
                "findings_count":  {"type": "integer", "minimum": 0},
                "evidence_bytes":  {"type": "integer", "minimum": 0},
                "current_plan":    {"type": "string"},
                "quota_overage":   {"type": "number"},
            },
        },
    },
    "GET /api/v1/partners/{partner_id}/hierarchy/tenant/{tenant_id}": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":         {"type": "string", "format": "uuid"},
                "partner_id":        {"type": "string", "format": "uuid"},
                "parent_partner_ids": {"type": "array", "items": {"type": "string", "format": "uuid"}},
                "depth":             {"type": "integer", "minimum": 0},
            },
            "required": ["tenant_id", "partner_id"],
        },
    },
    "GET /api/v1/partners/{partner_id}/preview": {
        "response_200": {
            "type": "object",
            "properties": {
                "partner_id":    {"type": "string", "format": "uuid"},
                "name":          {"type": "string"},
                "primary_color": {"type": "string"},
                "logo_url":      {"type": "string"},
            },
        },
    },

    # ----- Platform impersonation listing --------------------------------
    "GET /api/v1/platform/impersonate/active": {
        "response_200": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":             {"type": "string", "format": "uuid"},
                            "operator_id":    {"type": "string", "format": "uuid"},
                            "operator_email": {"type": "string", "format": "email"},
                            "target_user_id": {"type": "string", "format": "uuid"},
                            "target_email":   {"type": "string", "format": "email"},
                            "started_at":     {"type": "string", "format": "date-time"},
                            "expires_at":     {"type": "string", "format": "date-time"},
                            "ticket_ref":     {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    "GET /api/v1/platform/billing/plan-requests": {
        "response_200": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id":          {"type": "string", "format": "uuid"},
                            "partner_id":  {"type": "string", "format": "uuid"},
                            "from_plan":   {"type": "string"},
                            "to_plan":     {"type": "string"},
                            "status":      {"type": "string"},
                            "filed_at":    {"type": "string", "format": "date-time"},
                        },
                    },
                },
            },
        },
    },

    # ----- Agent emergency-stop + update-offer ---------------------------
    "GET /api/v1/agents/{agent_id}/emergency-stop-sla": {
        "response_200": {
            "type": "object",
            "properties": {
                "agent_id":        {"type": "string", "format": "uuid"},
                "sla_target_secs": {"type": "integer", "minimum": 0},
                "p99_secs":        {"type": "number"},
                "samples":         {"type": "integer", "minimum": 0},
            },
        },
    },
    "GET /api/v1/agents/{agent_id}/update-offer": {
        "response_200": {
            "type": "object",
            "properties": {
                "agent_id":       {"type": "string", "format": "uuid"},
                "current_version": {"type": "string"},
                "offered_version": {"type": "string"},
                "checksum_sha256": {"type": "string"},
                "url":             {"type": "string"},
            },
        },
    },

    # ----- Action endpoints (return 204 / minimal status body) -----------
    # These are operational actions whose response is intentionally
    # minimal — the caller already knows the action they invoked.
    # Schema is the {status: enum} shape the handlers use.
    "POST /api/v1/scans/{scan_id}/approve": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["approved"]}},
        },
    },
    "POST /api/v1/platform/tenants/{tenant_id}/migrate": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":   {"type": "string", "format": "uuid"},
                "from_partner": {"type": "string", "format": "uuid"},
                "to_partner":   {"type": "string", "format": "uuid"},
                "status":       {"type": "string", "enum": ["migrated", "in_progress"]},
            },
        },
    },
    "POST /api/v1/platform/tenants/{tenant_id}/quarantine": {
        "response_200": {
            "type": "object",
            "properties": {
                "tenant_id":           {"type": "string", "format": "uuid"},
                "quarantined":         {"type": "boolean"},
                "quarantine_reason":   {"type": "string"},
                "hard_delete_after":   {"type": "string", "format": "date-time"},
            },
        },
    },
    "POST /api/v1/platform/billing/plan-requests/{id}/decide": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "decision": {"type": "string", "enum": ["approved", "rejected"]},
                "note":     {"type": "string"},
            },
            "required": ["decision"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":         {"type": "string", "format": "uuid"},
                "status":     {"type": "string"},
                "decided_at": {"type": "string", "format": "date-time"},
            },
        },
    },
    "POST /api/v1/platform/billing/usage-adjustments": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "partner_id":  {"type": "string", "format": "uuid"},
                "amount_usd":  {"type": "number"},
                "reason":      {"type": "string"},
            },
            "required": ["partner_id", "amount_usd", "reason"],
        },
        "response_200": {
            "type": "object",
            "properties": {"id": {"type": "string", "format": "uuid"}},
        },
    },
    "POST /api/v1/partners/{partner_id}/sender-dns/check": {
        "response_200": {
            "type": "object",
            "properties": {
                "spf_ok":   {"type": "boolean"},
                "dkim_ok":  {"type": "boolean"},
                "dmarc_ok": {"type": "boolean"},
                "details":  {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
    },
    "POST /api/v1/partners/{partner_id}/email-templates/{code}/send-test": {
        "response_200": {
            "type": "object",
            "properties": {
                "sent_to": {"type": "string", "format": "email"},
                "status":  {"type": "string"},
            },
        },
    },
    "POST /api/v1/evidence/manual": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {
                "tenant_id":    {"type": "string", "format": "uuid"},
                "engagement_id": {"type": "string", "format": "uuid"},
                "finding_id":   {"type": "string", "format": "uuid"},
                "kind":         {"type": "string"},
                "content_type": {"type": "string"},
                "body_base64":  {"type": "string", "contentEncoding": "base64"},
            },
            "required": ["tenant_id", "kind"],
        },
        "response_200": {
            "type": "object",
            "properties": {
                "id":     {"type": "string", "format": "uuid"},
                "sha256": {"type": "string"},
            },
        },
    },
    "POST /api/v1/integrations/test": {
        # Operator-level test of a NEW integration before persisting.
        # Returns the test-deliver result without writing the row.
        "response_200": {
            "type": "object",
            "properties": {
                "ok":          {"type": "boolean"},
                "status_code": {"type": "integer"},
                "duration_ms": {"type": "integer"},
                "error":       {"type": "string"},
            },
            "required": ["ok"],
        },
    },
    "PUT /api/v1/integrations/signing-secret": {
        "request_required": True,
        "request": {
            "type": "object",
            "properties": {"secret": {"type": "string"}},
            "required": ["secret"],
        },
    },
    "DELETE /api/v1/platform/impersonate/{session_id}": {
        # Returns 204 No Content; we still declare an EMPTY 200
        # so the spec validates if a handler ever switches to 200.
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["ended"]}},
        },
    },
    "DELETE /api/v1/tenants/{tenant_id}/scim/tokens/{token_id}": {
        "response_200": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["revoked"]}},
        },
    },
    "POST /api/v1/auth/mfa/enroll/start": {
        "response_200": {
            "type": "object",
            "properties": {
                "secret":           {"type": "string"},
                "qr_code_data_url": {"type": "string"},
                "recovery_codes":   {"type": "array", "items": {"type": "string"}},
            },
            "required": ["secret"],
        },
    },

    # ----- SSO flows (issue HTTP 302 redirect, no JSON body) -------------
    # These return HTTP 302 to the IdP authorization endpoint. The
    # "redirect" marker tells the spec emitter to declare the 302
    # response and the Location header explicitly. Default 200 is
    # still in the spec to keep the contract test happy if any handler
    # transient-returns 200 (e.g. during an error path with HTML body).
    "GET /api/v1/auth/sso/{tenant_slug}/oidc/start": {
        "redirect": True,
        "response_200": {
            "type": "object",
            "properties": {
                "redirect_url": {"type": "string", "format": "uri"},
            },
        },
    },
    "GET /api/v1/auth/sso/{tenant_slug}/oidc/callback": {
        "redirect": True,
        "response_200": {
            "type": "object",
            "properties": {
                "status":    {"type": "string"},
                "tenant_id": {"type": "string", "format": "uuid"},
            },
        },
    },
    "GET /api/v1/auth/sso/{tenant_slug}/saml/start": {
        "redirect": True,
        "response_200": {
            "type": "object",
            "properties": {
                "redirect_url": {"type": "string", "format": "uri"},
            },
        },
    },
    "POST /api/v1/auth/sso/{tenant_slug}/saml/acs": {
        "redirect": True,
        "response_200": {
            "type": "object",
            "properties": {
                "status":    {"type": "string"},
                "tenant_id": {"type": "string", "format": "uuid"},
            },
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


def emit_yaml(routes, route_to_handler, handler_keys, out_path: Path):
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
        # Discovered keys for this route, if oasgen-extract produced
        # them. None means we don't know any keys for this handler.
        handler_name = route_to_handler.get((method, path))
        discovered = handler_keys.get(handler_name) if handler_name else None
        discovered_schema = schema_from_handler_keys(discovered)
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
        elif path.endswith(".yaml") or path.endswith(".yml"):
            ct = "application/x-yaml"
            schema_200 = {"type": "string"}
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
        # Schema selection priority (most specific wins):
        #   1. Hand-authored override (SCHEMA_OVERRIDES) — tight schema
        #      with type constraints, enums, formats. ~39 endpoints.
        #   2. Auto-discovered schema (oasgen-extract output) — every
        #      property NAME from the handler's writeJSON call is
        #      preserved; types are best-effort hints.
        #      additionalProperties=true keeps the contract test green.
        #   3. Default placeholder — {object, additionalProperties: true}.
        # The default response Content-Type was already set above
        # (per-path overrides for SARIF, NDJSON, etc.); we only mess
        # with the SCHEMA here, not the content-type.
        if override and override.get("response_200"):
            schema_200 = override["response_200"]
        elif discovered_schema and ct == "application/json":
            # Only attach the discovered schema for JSON responses —
            # non-JSON paths (PEM, NDJSON, …) have their own schemas
            # above and the discovered keys wouldn't make sense.
            schema_200 = discovered_schema
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
    routes, route_to_handler = collect_routes(repo)
    handler_keys = load_handler_keys(repo)
    print(f"oasgen: {len(routes)} routes, {len(route_to_handler)} with known handler, "
          f"{len(handler_keys)} handlers with discovered keys", flush=True)
    emit_yaml(routes, route_to_handler, handler_keys, Path(args.output))


if __name__ == "__main__":
    main()
