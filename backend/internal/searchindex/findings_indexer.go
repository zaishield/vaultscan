// findings_indexer.go — bridges findings.Service.Upsert events into
// the OpenSearch findings index.
//
// Wiring (cmd/api/main.go):
//   indexer := searchindex.NewFindingsIndexer(client)
//   bus.Subscribe(eventbus.FindingNormalized, indexer.HandleEvent)
//
// Idempotent: every Upsert (new or dedup) re-indexes the doc, so a
// missed event during an OpenSearch outage is recovered by the next
// activity on that finding.
package searchindex

import (
	"context"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// FindingsIndexName is the alias every API write targets. Production
// rotates the underlying index periodically (template + ISM policy).
const FindingsIndexName = "vaultscan-findings"

// AuditIndexName ditto for audit_logs.
const AuditIndexName = "vaultscan-audit"

type FindingsIndexer struct {
	client *Client
}

func NewFindingsIndexer(c *Client) *FindingsIndexer { return &FindingsIndexer{client: c} }

// HandleEvent is bus.Subscribe-shaped. The payload of a
// FindingCreated event carries finding_id + tenant_id + the searchable
// fields (title, severity, scanner, affected_endpoint).
//
// Tenant guard: an event WITHOUT TenantID is refused outright. A
// spoofed event with no tenant would index a finding under the
// platform-wide bucket where any tenant-scoped query could match
// it. The event bus durability layer makes the publisher
// responsible for setting TenantID; the indexer treats its absence
// as a bug worth refusing rather than fixing up.
func (idx *FindingsIndexer) HandleEvent(ctx context.Context, ev eventbus.Event) {
	if ev.Type != eventbus.FindingNormalized {
		return
	}
	id, _ := ev.Payload["finding_id"].(string)
	if id == "" {
		return
	}
	if ev.TenantID == nil {
		// Don't index untyped/unscoped findings — refusing here is
		// safer than indexing with tenant_id=null which would
		// short-circuit downstream tenant filters.
		return
	}
	doc := map[string]any{
		"finding_id":         id,
		"tenant_id":          ev.TenantID,
		"partner_id":         ev.PartnerID,
		"title":              ev.Payload["title"],
		"severity":           ev.Payload["severity"],
		"scanner":            ev.Payload["scanner"],
		"affected_endpoint":  ev.Payload["affected_endpoint"],
		"status":             ev.Payload["status"],
		"updated_at":         ev.Payload["last_seen"],
	}
	routing := ""
	if ev.TenantID != nil {
		routing = ev.TenantID.String()
	}
	// Best-effort: an OpenSearch outage shouldn't fail the upsert
	// hot path. The event is durable in bus_events so a backfill job
	// can replay missed indexings.
	_ = idx.client.IndexDoc(ctx, FindingsIndexName, id, doc, routing)
}

// FindingsIndexMapping is the mapping the EnsureIndex call should pass.
func FindingsIndexMapping() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 1,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"finding_id":        map[string]any{"type": "keyword"},
				"tenant_id":         map[string]any{"type": "keyword"},
				"partner_id":        map[string]any{"type": "keyword"},
				"title":             map[string]any{"type": "text"},
				"severity":          map[string]any{"type": "keyword"},
				"scanner":           map[string]any{"type": "keyword"},
				"affected_endpoint": map[string]any{"type": "keyword"},
				"status":            map[string]any{"type": "keyword"},
				"updated_at":        map[string]any{"type": "date"},
			},
		},
	}
}

// AuditIndexMapping mirrors FindingsIndexMapping for audit_logs rows.
func AuditIndexMapping() map[string]any {
	return map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 1,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"audit_id":    map[string]any{"type": "long"},
				"event":       map[string]any{"type": "keyword"},
				"actor_id":    map[string]any{"type": "keyword"},
				"actor_type":  map[string]any{"type": "keyword"},
				"tenant_id":   map[string]any{"type": "keyword"},
				"partner_id":  map[string]any{"type": "keyword"},
				"target_type": map[string]any{"type": "keyword"},
				"target_id":   map[string]any{"type": "keyword"},
				"payload":     map[string]any{"type": "object", "enabled": false},
				"occurred_at": map[string]any{"type": "date"},
			},
		},
	}
}
