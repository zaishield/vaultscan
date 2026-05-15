# VS-11 · Integrations & Event Bus

| Acceptance Criterion                                                              | Implementation |
|-----------------------------------------------------------------------------------|----------------|
| All 21 event types defined in §22.1 published                                      | `backend/internal/eventbus/eventbus.go` exposes `AllEventTypes()` (21 entries); test asserts count |
| Jira integration creates issue for new Critical finding automatically              | `integrations.Service.fanout` filters by event_filter; Jira integration consumes `FindingNormalized` events |
| SIEM forwarding delivers structured event payload for each audit event             | `integrations` SIEM type emits standard envelope `{event_id, event_type, tenant_id, payload}` |
| Webhook delivery retried up to 5 times with exponential backoff                    | `integrations.deliver` loop: 5 attempts, 1s → 2s → 4s → 8s → 16s |
| Slack/Teams notifications fire on `EmergencyStopTriggered`                         | `eventbus.EmergencyStopTriggered` published by `scanorch.EmergencyStop`; integrations subscribe to all event types via `Wire(bus)` |
| Integration credentials stored in secrets manager — never plain DB                  | `integrations.config.secret_ref` is a pointer into OpenBao/Infisical; `secrets.EnvBackend` resolves at delivery time |

## Supported integrations

```
jira, servicenow, slack, teams, webhook, siem, gitlab, github, jenkins, sentinel
```

## Key files

- `backend/migrations/0009_integrations_audit.up.sql`
- `backend/internal/eventbus/eventbus.go` + `eventbus_test.go`
- `backend/internal/integrations/service.go`
- `frontend/src/pages/Integrations.tsx`
