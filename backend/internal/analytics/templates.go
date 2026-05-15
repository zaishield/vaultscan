package analytics

import "context"

// Index names. Per-tenant indexes would scale better at very large fleets;
// the default is platform-wide indexes with mandatory tenant_id keyword
// fields used as routing keys.
const (
	IndexFindings  = "vaultscan-findings"
	IndexScanJobs  = "vaultscan-scan-jobs"
	IndexAgents    = "vaultscan-agents"
	IndexAssets    = "vaultscan-assets"
	IndexAuditLogs = "vaultscan-audit-logs"
)

// EnsureTemplates declares one index template per logical surface. Templates
// are idempotent; running on every API boot is safe.
func EnsureTemplates(ctx context.Context, c *Client) error {
	for _, t := range templates() {
		if err := c.EnsureTemplate(ctx, t.name, t.body); err != nil {
			return err
		}
	}
	return nil
}

type tmpl struct {
	name string
	body map[string]any
}

func templates() []tmpl {
	return []tmpl{
		{
			name: "vaultscan-findings",
			body: map[string]any{
				"index_patterns": []string{IndexFindings + "*"},
				"template": map[string]any{
					"settings": map[string]any{
						"number_of_shards":   1,
						"number_of_replicas": 1,
						"refresh_interval":   "5s",
					},
					"mappings": map[string]any{
						"properties": map[string]any{
							"id":                kw,
							"tenant_id":         kw,
							"partner_id":        kw,
							"engagement_id":     kw,
							"asset_id":          kw,
							"scan_job_id":       kw,
							"title":             text,
							"description":       text,
							"severity":          kw,
							"status":            kw,
							"scanner":           kw,
							"scan_type":         kw,
							"affected_endpoint": kw,
							"port":              integer,
							"protocol":          kw,
							"cve":               kw,
							"cwe":               kw,
							"cvss_score":        floatField,
							"first_seen":        date,
							"last_seen":         date,
							"dedup_fingerprint": kw,
						},
					},
				},
			},
		},
		{
			name: "vaultscan-scan-jobs",
			body: map[string]any{
				"index_patterns": []string{IndexScanJobs + "*"},
				"template": map[string]any{
					"settings": map[string]any{
						"number_of_shards":   1,
						"number_of_replicas": 1,
					},
					"mappings": map[string]any{
						"properties": map[string]any{
							"id":            kw,
							"tenant_id":     kw,
							"partner_id":    kw,
							"engagement_id": kw,
							"profile_code":  kw,
							"plane":         kw,
							"region":        kw,
							"agent_id":      kw,
							"status":        kw,
							"target_count":  integer,
							"started_at":    date,
							"completed_at":  date,
							"created_at":    date,
						},
					},
				},
			},
		},
		{
			name: "vaultscan-agents",
			body: map[string]any{
				"index_patterns": []string{IndexAgents + "*"},
				"template": map[string]any{
					"mappings": map[string]any{
						"properties": map[string]any{
							"id":             kw,
							"tenant_id":      kw,
							"partner_id":     kw,
							"name":           kw,
							"status":         kw,
							"version":        kw,
							"cpu_percent":    floatField,
							"memory_percent": floatField,
							"last_heartbeat": date,
						},
					},
				},
			},
		},
		{
			name: "vaultscan-assets",
			body: map[string]any{
				"index_patterns": []string{IndexAssets + "*"},
				"template": map[string]any{
					"mappings": map[string]any{
						"properties": map[string]any{
							"id":          kw,
							"tenant_id":   kw,
							"partner_id":  kw,
							"asset_type":  kw,
							"value":       kw,
							"plane":       kw,
							"criticality": kw,
							"environment": kw,
							"first_seen":  date,
							"last_seen":   date,
						},
					},
				},
			},
		},
		{
			name: "vaultscan-audit-logs",
			body: map[string]any{
				"index_patterns": []string{IndexAuditLogs + "*"},
				"template": map[string]any{
					"settings": map[string]any{
						"number_of_replicas": 1,
					},
					"mappings": map[string]any{
						"properties": map[string]any{
							"event":       kw,
							"actor_type":  kw,
							"actor_id":    kw,
							"target_type": kw,
							"target_id":   kw,
							"tenant_id":   kw,
							"partner_id":  kw,
							"occurred_at": date,
						},
					},
				},
			},
		},
	}
}

var (
	kw         = map[string]any{"type": "keyword"}
	text       = map[string]any{"type": "text"}
	integer    = map[string]any{"type": "integer"}
	floatField = map[string]any{"type": "float"}
	date       = map[string]any{"type": "date"}
)
