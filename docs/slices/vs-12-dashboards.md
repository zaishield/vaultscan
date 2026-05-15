# VS-12 · Dashboards & Visualization

| Acceptance Criterion                                                            | Implementation |
|---------------------------------------------------------------------------------|----------------|
| Executive Dashboard displays all 11 metrics from §7.4                           | `backend/internal/dashboards/service.go` `Executive` populates 11 fields; rendered in `frontend/src/pages/Dashboard.tsx` |
| Technical Dashboard displays all 12 metric categories from §7.4                 | `Technical` returns 12 categories (severity, asset, scanner, ports, services, TLS, AD, cloud, container, K8s, web/API) |
| Partner Dashboard displays all 8 metric categories from §7.4                    | `Partner` returns customers_managed, active_tenants, active_agents, scan_usage, license_usage, open_critical_across_tenants, expiring_engagements, billing_counters |
| Agent heartbeat change reflected within 30 seconds                              | `Dashboard` and `InternalAgents` pages refresh every 30s; bus emits `AgentHeartbeatReceived` |
| Partner admin sees only their own customers' data                               | All dashboard queries filter on `tenant_id` / `partner_id` from the identity; tenant middleware blocks cross-partner queries |
| Risk score changes when new Critical finding added                              | `dashboards.computeRiskScore` weights critical=10, high=5, sla_breach=7 |

## Key files

- `backend/internal/dashboards/service.go`
- `frontend/src/pages/Dashboard.tsx`
