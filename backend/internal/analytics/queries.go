package analytics

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Aggregator powers the dashboard widgets. It returns the same shape the
// Postgres-backed dashboards.Service returns, so the UI is unchanged.
type Aggregator struct{ c *Client }

func NewAggregator(c *Client) *Aggregator { return &Aggregator{c: c} }

// SeverityBreakdown returns counts by severity for a tenant.
func (a *Aggregator) SeverityBreakdown(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"term": map[string]any{"tenant_id": tenantID.String()},
		},
		"aggs": map[string]any{
			"by_severity": map[string]any{
				"terms": map[string]any{"field": "severity", "size": 10},
			},
		},
	}
	res, err := a.c.Search(ctx, IndexFindings, q)
	if err != nil {
		return nil, err
	}
	return bucketCounts(res, "by_severity"), nil
}

// ScanTrend returns daily scan counts over the last `days` days.
func (a *Aggregator) ScanTrend(ctx context.Context, tenantID uuid.UUID, days int) ([]TrendBucket, error) {
	if days <= 0 {
		days = 14
	}
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{"term": map[string]any{"tenant_id": tenantID.String()}},
					map[string]any{"range": map[string]any{
						"created_at": map[string]any{"gte": fmt.Sprintf("now-%dd/d", days)},
					}},
				},
			},
		},
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "created_at",
					"calendar_interval": "1d",
					"format":            "yyyy-MM-dd",
				},
			},
		},
	}
	res, err := a.c.Search(ctx, IndexScanJobs, q)
	if err != nil {
		return nil, err
	}
	return histogramBuckets(res, "by_day"), nil
}

// FindingsByAsset returns the top N assets by finding count.
func (a *Aggregator) FindingsByAsset(ctx context.Context, tenantID uuid.UUID, top int) ([]KV, error) {
	if top <= 0 {
		top = 10
	}
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"term": map[string]any{"tenant_id": tenantID.String()},
		},
		"aggs": map[string]any{
			"by_asset": map[string]any{
				"terms": map[string]any{"field": "affected_endpoint", "size": top},
			},
		},
	}
	res, err := a.c.Search(ctx, IndexFindings, q)
	if err != nil {
		return nil, err
	}
	return bucketKV(res, "by_asset"), nil
}

// AgentHealth returns counts of agents by status.
func (a *Aggregator) AgentHealth(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	q := map[string]any{
		"size": 0,
		"query": map[string]any{
			"term": map[string]any{"tenant_id": tenantID.String()},
		},
		"aggs": map[string]any{
			"by_status": map[string]any{
				"terms": map[string]any{"field": "status", "size": 10},
			},
		},
	}
	res, err := a.c.Search(ctx, IndexAgents, q)
	if err != nil {
		return nil, err
	}
	return bucketCounts(res, "by_status"), nil
}

type TrendBucket struct {
	Date  string `json:"date"`
	Scans int    `json:"scans"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func bucketCounts(res map[string]any, aggName string) map[string]int {
	out := map[string]int{}
	aggs, _ := res["aggregations"].(map[string]any)
	if aggs == nil {
		return out
	}
	by, _ := aggs[aggName].(map[string]any)
	if by == nil {
		return out
	}
	buckets, _ := by["buckets"].([]any)
	for _, b := range buckets {
		bm, _ := b.(map[string]any)
		key, _ := bm["key"].(string)
		count, _ := bm["doc_count"].(float64)
		out[key] = int(count)
	}
	return out
}

func bucketKV(res map[string]any, aggName string) []KV {
	out := []KV{}
	aggs, _ := res["aggregations"].(map[string]any)
	if aggs == nil {
		return out
	}
	by, _ := aggs[aggName].(map[string]any)
	if by == nil {
		return out
	}
	buckets, _ := by["buckets"].([]any)
	for _, b := range buckets {
		bm, _ := b.(map[string]any)
		key, _ := bm["key"].(string)
		count, _ := bm["doc_count"].(float64)
		out = append(out, KV{Key: key, Count: int(count)})
	}
	return out
}

func histogramBuckets(res map[string]any, aggName string) []TrendBucket {
	out := []TrendBucket{}
	aggs, _ := res["aggregations"].(map[string]any)
	if aggs == nil {
		return out
	}
	by, _ := aggs[aggName].(map[string]any)
	if by == nil {
		return out
	}
	buckets, _ := by["buckets"].([]any)
	for _, b := range buckets {
		bm, _ := b.(map[string]any)
		date, _ := bm["key_as_string"].(string)
		count, _ := bm["doc_count"].(float64)
		out = append(out, TrendBucket{Date: date, Scans: int(count)})
	}
	return out
}
