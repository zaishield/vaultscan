# Runbook — WAF / edge rate-limit storm

## Symptom

- `vaultscan_request_total` drops sharply at the API while the
  edge-LB logs show traffic still arriving.
- Customers report intermittent 429 / 503 responses.
- Edge WAF dashboards show one or more IPs / ASNs / countries spiking.

## Initial triage

```bash
# Per-IP request rate (top 20 in the last 5 min) from the API logs:
kubectl logs -n vaultscan -l app=vaultscan-api --since=5m | \
  jq -r '.client_ip' | sort | uniq -c | sort -rn | head -20

# Or via Prometheus:
sum by (client_ip) (rate(vaultscan_request_total[5m]))

# WAF rate-limit hits:
sum by (rule, ip) (rate(waf_rate_limit_blocks_total[5m]))
```

## Decision tree

| Signal | Action |
| --- | --- |
| Single IP > 1k req/s | Block at WAF (90 min) — likely scraping or DoS |
| Many IPs, one ASN | Block ASN at WAF (24h) — likely a botnet |
| Distributed, low per-IP rate | Increase global rate-limit ceiling temporarily; investigate why |
| Targeted at one endpoint (`/auth/login`) | Tighten the per-route auth-surface limiter; force IP cool-down via `auth/ip-lockouts` |
| Legitimate burst (announced campaign / new customer onboarding) | Pre-warm the cluster (scale `api` + `agent-gateway` HPA min) + raise quota |

## Immediate mitigation

### Block via WAF (Cloudflare / AWS WAF / Azure Front Door)

Operator-specific. Reference per-cloud playbook:
- AWS: `aws wafv2 update-ip-set` against the regional WAF set
- Cloudflare: rule expression `(ip.src in {1.2.3.4})` with action: block
- Azure: Front Door custom rule with `RemoteAddr` match

Always:
1. Set TTL on the block (24h max for IP, 90 days for ASN).
2. Log the block to the on-call channel.
3. Open an issue tagged `waf-block` so the block lapses cleanly.

### Tighten in-app rate limit

```bash
# Increase the per-IP rate limit's strictness via env (requires
# rolling restart of the API):
kubectl set env -n vaultscan deployment/vaultscan-api \
  VAULTSCAN_RATE_LIMIT_RPS=50          # default is 100
kubectl rollout restart -n vaultscan deployment/vaultscan-api
```

### Lock out specific IPs (in-app)

If the attack is targeting `/api/v1/auth/login`:

```bash
# Add to the IP lockout list via the platform admin API
curl -X POST "$API/api/v1/auth/ip-lockouts" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"ip":"1.2.3.4","reason":"brute-force /auth/login","expires_in":"24h"}'
```

The `bruteforce_shield` middleware blocks the IP at the API ingress
without going through the rest of the auth pipeline.

## Don'ts

- **Do NOT** disable the rate limiter entirely. Better to surface
  429s to legitimate users than to let the DB pool exhaust.
- **Do NOT** scale `api` infinitely. Past 10x baseline replicas
  you'll overwhelm Postgres before you serve any meaningful extra
  traffic.
- **Do NOT** block at the IP layer indefinitely. Set TTLs.

## Postmortem questions

- Was the attack credentialed (failed-auth) or anonymous (anon GET)?
- Was the WAF rule reactive (we set it during the incident) or
  proactive (already there + just blocked)?
- Can we add a `vaultscan_unique_client_ips` metric and alert when
  it doubles over 5 min?
- Did the autoscaler thrash? See `cluster-autoscaler-thrash.md`.

## Related

- `incident-response.md` (parent: incident classification)
- `cluster-autoscaler-thrash.md` (consequence)
- `capacity-planning.md` (what RPS we should sustain)
