package analytics

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// Indexer mirrors authoritative Postgres records into OpenSearch when bus
// events fire. It batches writes per flush interval to bound load on the
// search cluster.
type Indexer struct {
	client        *Client
	pool          *pgxpool.Pool
	log           zerolog.Logger
	flushInterval time.Duration
	maxBatch      int

	mu    sync.Mutex
	queue []BulkOp
}

func NewIndexer(c *Client, pool *pgxpool.Pool, log zerolog.Logger) *Indexer {
	return &Indexer{
		client:        c,
		pool:          pool,
		log:           log.With().Str("component", "analytics-indexer").Logger(),
		flushInterval: 2 * time.Second,
		maxBatch:      500,
	}
}

// Wire subscribes the indexer to every event type that maps to an indexable
// surface.
func (i *Indexer) Wire(bus *eventbus.Bus) {
	for _, et := range []string{
		eventbus.FindingNormalized,
		eventbus.FindingDeduplicated,
		eventbus.FindingAssigned,
		eventbus.ScanJobCreated,
		eventbus.ScanJobApproved,
		eventbus.ExternalScanStarted,
		eventbus.InternalScanDispatched,
		eventbus.AgentHeartbeatReceived,
		eventbus.AgentWentOffline,
		eventbus.RetestPassed,
		eventbus.RetestFailed,
	} {
		etCopy := et
		bus.Subscribe(etCopy, func(ctx context.Context, ev eventbus.Event) {
			i.handle(ctx, ev)
		})
	}
}

// Run blocks until ctx is cancelled, flushing the batch periodically.
func (i *Indexer) Run(ctx context.Context) {
	t := time.NewTicker(i.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			i.flush(context.Background())
			return
		case <-t.C:
			i.flush(ctx)
		}
	}
}

func (i *Indexer) handle(ctx context.Context, ev eventbus.Event) {
	switch ev.Type {
	case eventbus.FindingNormalized,
		eventbus.FindingDeduplicated,
		eventbus.FindingAssigned,
		eventbus.RetestPassed,
		eventbus.RetestFailed:
		fid, ok := stringFromPayload(ev.Payload, "finding_id")
		if !ok {
			return
		}
		i.queueFinding(ctx, fid)
	case eventbus.ScanJobCreated,
		eventbus.ScanJobApproved,
		eventbus.ExternalScanStarted,
		eventbus.InternalScanDispatched:
		jid, ok := stringFromPayload(ev.Payload, "scan_job_id")
		if !ok {
			return
		}
		i.queueScanJob(ctx, jid)
	case eventbus.AgentHeartbeatReceived,
		eventbus.AgentWentOffline:
		aid, ok := stringFromPayload(ev.Payload, "agent_id")
		if !ok {
			return
		}
		i.queueAgent(ctx, aid)
	}
	if i.length() >= i.maxBatch {
		i.flush(ctx)
	}
}

func (i *Indexer) queueFinding(ctx context.Context, id string) {
	row := i.pool.QueryRow(ctx, `
		SELECT id, tenant_id, partner_id, engagement_id, asset_id, scan_job_id,
		       title, COALESCE(description,''), severity, status, scanner, scan_type,
		       COALESCE(affected_endpoint,''), COALESCE(port,0), COALESCE(protocol,''),
		       COALESCE(cve,''), COALESCE(cwe,''), COALESCE(cvss_score,0),
		       first_seen, last_seen, dedup_fingerprint
		  FROM findings WHERE id=$1`, id)
	var (
		idCol, tenantID, partnerID, engID                                 string
		assetID, scanJobID                                                *string
		title, description, severity, status, scanner, scanType, endpoint string
		port                                                              int
		protocol, cve, cwe                                                string
		cvss                                                              float64
		firstSeen, lastSeen                                               time.Time
		fingerprint                                                       string
	)
	if err := row.Scan(&idCol, &tenantID, &partnerID, &engID, &assetID, &scanJobID,
		&title, &description, &severity, &status, &scanner, &scanType, &endpoint,
		&port, &protocol, &cve, &cwe, &cvss, &firstSeen, &lastSeen, &fingerprint); err != nil {
		i.log.Debug().Err(err).Str("id", id).Msg("queueFinding scan")
		return
	}
	doc := map[string]any{
		"id":                idCol,
		"tenant_id":         tenantID,
		"partner_id":        partnerID,
		"engagement_id":     engID,
		"title":             title,
		"description":       description,
		"severity":          severity,
		"status":            status,
		"scanner":           scanner,
		"scan_type":         scanType,
		"affected_endpoint": endpoint,
		"port":              port,
		"protocol":          protocol,
		"cve":               cve,
		"cwe":               cwe,
		"cvss_score":        cvss,
		"first_seen":        firstSeen,
		"last_seen":         lastSeen,
		"dedup_fingerprint": fingerprint,
	}
	if assetID != nil {
		doc["asset_id"] = *assetID
	}
	if scanJobID != nil {
		doc["scan_job_id"] = *scanJobID
	}
	i.enqueue(BulkOp{Action: "index", Index: IndexFindings, ID: id, Doc: doc})
}

func (i *Indexer) queueScanJob(ctx context.Context, id string) {
	row := i.pool.QueryRow(ctx, `
		SELECT j.id, j.tenant_id, j.partner_id, j.engagement_id, p.code,
		       j.plane, COALESCE(j.region,''), j.agent_id, j.status,
		       jsonb_array_length(j.targets), j.started_at, j.completed_at, j.created_at
		  FROM scan_jobs j JOIN scan_profiles p ON p.id = j.profile_id
		 WHERE j.id=$1`, id)
	var (
		idCol, tenantID, partnerID, engID, profileCode, plane, region, status string
		agentID                                                               *string
		targetCount                                                           int
		startedAt, completedAt                                                *time.Time
		createdAt                                                             time.Time
	)
	if err := row.Scan(&idCol, &tenantID, &partnerID, &engID, &profileCode,
		&plane, &region, &agentID, &status, &targetCount, &startedAt, &completedAt,
		&createdAt); err != nil {
		i.log.Debug().Err(err).Str("id", id).Msg("queueScanJob scan")
		return
	}
	doc := map[string]any{
		"id": idCol, "tenant_id": tenantID, "partner_id": partnerID,
		"engagement_id": engID, "profile_code": profileCode,
		"plane": plane, "region": region, "status": status,
		"target_count": targetCount, "created_at": createdAt,
	}
	if agentID != nil {
		doc["agent_id"] = *agentID
	}
	if startedAt != nil {
		doc["started_at"] = *startedAt
	}
	if completedAt != nil {
		doc["completed_at"] = *completedAt
	}
	i.enqueue(BulkOp{Action: "index", Index: IndexScanJobs, ID: id, Doc: doc})
}

func (i *Indexer) queueAgent(ctx context.Context, id string) {
	row := i.pool.QueryRow(ctx, `
		SELECT id, tenant_id, partner_id, name, status, COALESCE(version,''),
		       COALESCE(cpu_percent,0), COALESCE(memory_percent,0), last_heartbeat
		  FROM agents WHERE id=$1`, id)
	var (
		idCol, tenantID, partnerID, name, status, version string
		cpu, mem                                          float64
		lastHB                                            *time.Time
	)
	if err := row.Scan(&idCol, &tenantID, &partnerID, &name, &status, &version,
		&cpu, &mem, &lastHB); err != nil {
		i.log.Debug().Err(err).Str("id", id).Msg("queueAgent scan")
		return
	}
	doc := map[string]any{
		"id": idCol, "tenant_id": tenantID, "partner_id": partnerID,
		"name": name, "status": status, "version": version,
		"cpu_percent": cpu, "memory_percent": mem,
	}
	if lastHB != nil {
		doc["last_heartbeat"] = *lastHB
	}
	i.enqueue(BulkOp{Action: "index", Index: IndexAgents, ID: id, Doc: doc})
}

func (i *Indexer) enqueue(op BulkOp) {
	i.mu.Lock()
	i.queue = append(i.queue, op)
	i.mu.Unlock()
}

func (i *Indexer) length() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.queue)
}

func (i *Indexer) flush(ctx context.Context) {
	i.mu.Lock()
	if len(i.queue) == 0 {
		i.mu.Unlock()
		return
	}
	batch := i.queue
	i.queue = nil
	i.mu.Unlock()
	if err := i.client.Bulk(ctx, batch); err != nil {
		i.log.Warn().Err(err).Int("count", len(batch)).Msg("opensearch bulk failed; will rebuild on next event")
		return
	}
	i.log.Debug().Int("count", len(batch)).Msg("flushed batch to opensearch")
}

func stringFromPayload(p map[string]any, key string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p[key]
	if !ok {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	if s, ok := v.(interface{ String() string }); ok {
		return s.String(), true
	}
	return "", false
}
