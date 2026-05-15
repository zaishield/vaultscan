# Operations Runbooks

Single index for the operational procedures the SRE / on-call team
runs against VAULTSCAN. Every runbook here is the authoritative
procedure — if reality diverges, the runbook is wrong and someone
has to PR a fix. Drift is a P2 ticket.

| Runbook | Frequency | Last drilled |
|---|---|---|
| [On-call playbook](on-call.md) | Continuous | — |
| [Incident response](incident-response.md) | As needed | — |
| [Disaster recovery](disaster-recovery.md) | Quarterly | — |
| [Multi-region failover](multi-region-failover.md) | Annually | — |
| [Agent fleet onboarding](agent-fleet-onboarding.md) | Per customer | — |
| [Pentest engagement kickoff](pentest-engagement-kickoff.md) | Per engagement | — |
| [Tenant offboarding / GDPR erasure](tenant-offboarding.md) | Per request | — |
| [Compliance audit prep](compliance-audit-prep.md) | Annually | — |
| [Scanner-image release](scanner-image-release.md) | On tool update | — |
| [Cosign trust-key rotation](cosign-key-rotation.md) | Yearly | — |
| [KEK / DEK rotation](kek-dek-rotation.md) | Yearly | — |
| [JWT signing-key rotation](jwt-key-rotation.md) | Quarterly | — |
| [Local-dev setup](local-dev.md) | — | — |

## Conventions

- Every runbook starts with **Pre-conditions** (what state the system
  must be in before you run it).
- Every step has a **Verification** line. If you can't verify, you
  can't move on.
- Anything that mutates customer data (delete, encrypt-in-place,
  re-issue) needs **two-person sign-off** — both names + ticket
  numbers go in the audit footer.
- Audit footer entries must reference an `audit_logs` row id.
