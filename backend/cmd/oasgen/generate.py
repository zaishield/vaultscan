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
ROUTE_RX = re.compile(r'\.(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"')


def collect_routes(repo_root: Path):
    """Walk handlers*.go + server.go, return sorted [(method, path), ...]."""
    api_dir = repo_root / "backend" / "internal" / "api"
    routes = set()
    for f in api_dir.glob("*.go"):
        for m in ROUTE_RX.finditer(f.read_text()):
            method, path = m.group(1).upper(), m.group(2)
            # Filter out static / non-API routes for the spec.
            if not path.startswith("/api/v1") and path != "/healthz" \
                    and path != "/.well-known/jwks.json":
                continue
            routes.add((method, path))
    return sorted(routes)


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
    """method_segments_from_path → camelCase operationId."""
    p = path.removeprefix("/api/v1/")
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


SUMMARY_HINTS = {
    "GET /api/v1/marketplace/listings": "List partner integration marketplace catalog.",
    "POST /api/v1/marketplace/installs": "Install a marketplace listing for the calling tenant.",
    "PATCH /api/v1/marketplace/installs/{install_id}": "Configure a pending marketplace install.",
    "DELETE /api/v1/marketplace/installs/{install_id}": "Uninstall (soft-suspend) a marketplace install.",
    "GET /api/v1/marketplace/installs": "List the calling tenant's marketplace installs.",
    "POST /api/v1/feedback": "Submit user feedback (bug/feature/NPS).",
    "POST /api/v1/feedback/dismiss-nps": "Hide the NPS prompt for the current session.",
    "GET /api/v1/feedback": "List feedback items (admin/triage view).",
    "PATCH /api/v1/feedback/{feedback_id}": "Triage a feedback item.",
    "POST /api/v1/mobile/devices": "Enroll a mobile device with a push token.",
    "DELETE /api/v1/mobile/devices/{device_id}": "Revoke a mobile device.",
    "GET /api/v1/mobile/dashboard": "Read the mobile-portal dashboard summary.",
    "POST /api/v1/mobile/alerts/ack": "Acknowledge a push-notification alert.",
    "POST /api/v1/mobile/emergency-stop": "Mobile-initiated emergency stop.",
    "GET /api/v1/.well-known/jwks.json": "JSON Web Key Set for JWT verification.",
    "GET /api/v1/orchestrator/public-key": "Cloud orchestrator's public key (PEM).",
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
        if method in ("POST", "PUT", "PATCH"):
            op["requestBody"] = {
                "required": False,
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "additionalProperties": True},
                    },
                },
            }
        op["responses"] = {
            "200": {
                "description": "Success",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "additionalProperties": True},
                    },
                },
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
                            emit(v, indent + 1)
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
