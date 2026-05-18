# Customer onboarding guide

Walkthrough for a new customer (and their VaultScan tenant admin)
going from "contract signed" to "first useful scan complete."

Estimated total time: 60-120 minutes spread across 1-2 weeks
(most of the wait is customer-side scheduling, not actual work).

## Day 0 — Account provisioning (VaultScan-side, ~30 min)

1. Sales hand-off received: customer name, plan, residency region,
   contracted features.
2. Create the partner:
   ```bash
   curl -X POST "$API/api/v1/partners" \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"name":"<customer>","slug":"<slug>","plan":"<plan>","region":"<eu|us|apac>"}'
   ```
3. Create the initial tenant under that partner.
4. Set residency pin if contracted:
   ```bash
   curl -X PUT "$API/api/v1/tenants/$TENANT_ID/residency" \
     -d '{"region":"eu","reason":"MSA §4.2"}'
   ```
5. Invite the customer's first admin user (via SCIM if they have it,
   or manual /users POST with a one-time enrollment link).
6. Email the customer:
   - Their admin's enrollment link
   - Link to https://docs.vaultscan.zaishield.com/getting-started
   - Their named CSM / TAM contact
   - Estimated time to first scan

## Day 1 — Customer admin completes setup (~30 min)

Customer follows the in-app onboarding wizard, which walks them through:

### 1. Sign in + MFA enrollment

- Click the enrollment link from the welcome email
- Set their password
- Enrol MFA (TOTP via Authenticator / Authy / 1Password; recovery codes shown once)
- MFA is REQUIRED for admin role; non-admin users can opt in
- Customer-facing doc: `https://docs.vaultscan.zaishield.com/mfa`

### 2. Configure SSO (optional, recommended)

If they have an IdP:
- Settings → Authentication → SAML / OIDC
- Paste their IdP metadata XML / discovery URL
- Map IdP claims to VaultScan roles (admin / member / read-only)
- Test login from the IdP — should complete without password prompt

If they have SCIM (Okta / Azure AD / OneLogin / etc.):
- Settings → Authentication → SCIM
- Generate the SCIM token + share with their IdP admin
- IdP admin configures the SCIM provisioning connector
- New users assigned to the VaultScan app in the IdP auto-provision

### 3. Define their first engagement

- Engagements are the unit of scoped scanning. One engagement per
  customer's "internal customer" (a department, a subsidiary, a
  pentest contract).
- Set scope: domains, IP ranges, cloud accounts.
- Upload (or self-sign) the authorization document — required
  before any scan can run.

### 4. Onboard their first scanner

Two paths:

**Path A: cloud-hosted scanners** (default for SaaS customers):
- No setup needed; VaultScan's scanner farm runs the tool
- Customer just creates a scan profile + clicks Run

**Path B: on-prem agent** (for customers with private networks):
- Settings → Agents → Provision new agent
- Copy the install command (one-line bash)
- Run on a Linux host inside their network
- Agent enrolls (mTLS, cert pinned)
- Now scans of their internal targets work end-to-end

Customer-facing doc: `https://docs.vaultscan.zaishield.com/agents`

### 5. Configure their first integration

Most common picks:
- Slack (post-scan summary to a channel)
- Jira (file tickets for High+ findings)
- SIEM (forward audit events)

See `integration-setup-guides.md` for the per-vendor walkthrough.

### 6. Run their first scan

- Create a scan profile (which tools to run, with what intensity)
- Schedule it (one-shot or recurring)
- Watch it in the live dashboard
- Review the findings + acknowledge / triage / risk-accept

## Week 1 follow-up (CSM)

Customer success manager reaches out 5 business days post-onboarding:
- Confirm the customer's done step 1-6 above
- Walk through their first findings report together
- Set up their compliance framework mapping if applicable
  (SOC2 / ISO27001 / PCI / HIPAA / GDPR)
- Identify any integration gaps

## Month 1 follow-up

- Capacity review: are they pushing the plan limits? Time to upgrade?
- Compliance pack: generate their first audit-ready evidence pack
  via `/api/v1/compliance/<framework>/engagements/<id>`
- Feedback: collect NPS via in-app prompt; route to product

## Common onboarding blockers

| Symptom | Cause | Fix |
| --- | --- | --- |
| Customer's IdP rejects our SAML request | Audience / ACS URL mismatch | Re-verify the EntityID + ACS URL in the SP metadata |
| Agent enrollment fails | mTLS cert chain issue, time skew on their host | NTP sync + check `agent-fleet-onboarding.md` |
| Scans queue but never run | Quota mis-set, scanner-worker not dispatching | See `scanner-job-stuck-pending.md` |
| Integration test passes but no events delivered | Wrong event filter on the integration config | Set event_filter to `.*` initially to confirm wiring, then tighten |
| Findings volume overwhelming | Scope too broad / intensity too high | Tune profile, enable dedup grouping |

## Internal handoff checklist

When CSM hands a customer back to support (post-onboarding):

- [ ] Tenant is in `active` status
- [ ] At least one admin user has MFA + has signed in twice
- [ ] At least one engagement has authorization on file
- [ ] At least one scan has completed successfully
- [ ] At least one integration is configured + has delivered an event
- [ ] Compliance framework (if contracted) is mapped to their controls
- [ ] Their named technical contact has been documented in CRM
- [ ] Welcome email + setup guide acknowledged

## Related

- `integration-setup-guides.md` — per-vendor integration setup
- `agent-fleet-onboarding.md` — agent provisioning detail
- `inbound-webhooks.md` — for customers pushing events INTO VaultScan
- `compliance-audit-prep.md` — pre-audit checklist
