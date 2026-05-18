# Role guides

Per-role handbooks. Each guide is the canonical one-pager for that
role's day-to-day. Cross-references to runbooks live inside.

| Role | Guide | Audience |
| --- | --- | --- |
| New developer | `developer.md` | Engineer joining the team |
| QA / tester | `qa-tester.md` | Manual + automated test execution |
| Platform admin (Day-1) | `platform-admin-day1.md` | First setup of a fresh deployment |
| Support engineer | `support-engineer.md` | Customer-issue debugging |
| SRE / on-call | `sre-on-call.md` | Production incident response |
| Finance / Billing Ops | `finance-billing.md` | Plan changes, usage rollup, dunning |
| Security Incident Commander | `security-incident-commander.md` | Sev-1 IC role |
| Compliance Officer | `compliance-officer.md` | Audit evidence pack workflow |
| Customer admin | `customer-admin.md` | Tenant administration (customer-side) |
| Auditor (external) | `auditor.md` | Read-only audit access |
| Integrator | `integrator.md` | Building on the VaultScan API |

## Conventions

- Each guide states the role's PRIMARY OBJECTIVE in one sentence
- Each lists the relevant API endpoints + CLI / Make targets
- Each links to the runbooks that role uses
- Each ends with a "When to escalate" section
