# Security Policy

## Supported versions

| Version | Status | Receives security fixes |
| --- | --- | --- |
| `1.x` (current) | Active | Yes |
| `0.x` | EOL | No — upgrade |

The latest minor of the current major always receives fixes. Older
minors receive backports only for Critical-severity issues at our
discretion.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security bugs.**

Send the report to **security@zaishield.com** with as much of the
following as you can provide:

1. A description of the vulnerability and its potential impact
2. The affected component(s) (URL paths, package names, version)
3. A reproducible proof of concept (curl / Burp HAR / sample code)
4. Your suggested CVSS 3.1 severity rating + vector
5. Whether you've shared this with anyone else (other vendors,
   public mailing lists, etc.)

Optionally PGP-encrypt to the fingerprint published at
`https://zaishield.com/security/pgp` (also linked from
[`/.well-known/security.txt`](https://api.vaultscan.zaishield.com/.well-known/security.txt)).

## What happens next

| Day | Action |
| --- | --- |
| 0 | You file the report. We acknowledge receipt within 24 hours. |
| 1-3 | We triage + reproduce. You receive a tracking ID + initial severity. |
| 7 | If Critical: a patch is in code review. |
| 30 | If High: a patch is in code review. |
| 60-90 | Coordinated public disclosure (the longer for Medium / Low). |

We follow a **90-day disclosure window** by default. If you need an
extension (for coordinated multi-vendor disclosure, regulatory
embargo, etc.) tell us — we'll honour reasonable requests.

## Safe-harbour

We will not pursue legal action against researchers who:
- Make a good-faith effort to comply with this policy
- Don't access or modify data beyond what's required to demonstrate the issue
- Don't disrupt other customers' access
- Don't violate any other applicable law

## Out of scope

The following are not security issues for the purpose of this policy:
- Self-XSS in fields the same user controls
- Missing security headers on non-API hosts (marketing pages, etc.)
- Findings from automated scanners without a working PoC
- Theoretical issues with no demonstrated impact
- Reports based on outdated software versions (please upgrade first)
- Volumetric / DDoS issues (covered separately by the WAF tier)

## Acknowledgments

Researchers who report valid vulnerabilities are credited (with their
consent) at
[`https://zaishield.com/security/acknowledgements`](https://zaishield.com/security/acknowledgements).

## Engineering process

Our internal engineering process for security issues is documented at
[`docs/operations/incident-response.md`](./docs/operations/incident-response.md).
External pentest scope is at
[`docs/operations/pentest-scope.md`](./docs/operations/pentest-scope.md).
