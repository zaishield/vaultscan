package dashboards

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

// ----- Per-user dashboard layouts -------------------------------------------

type Widget struct {
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`      // counter | line | bar | map | table | sse_log
	Title  string                 `json:"title"`
	X      int                    `json:"x"`
	Y      int                    `json:"y"`
	W      int                    `json:"w"`
	H      int                    `json:"h"`
	Config map[string]any         `json:"config,omitempty"`
}

type Layout struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	IsDefault bool       `json:"is_default"`
	Widgets   []Widget   `json:"widgets"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// SaveLayout creates or updates a per-user layout. If `isDefault` is true,
// any other layout for (user_id, role) loses its default flag.
func (s *Service) SaveLayout(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, name, role string, widgets []Widget, isDefault bool) (uuid.UUID, error) {
	if name == "" || role == "" {
		return uuid.Nil, errors.New("dashboards: layout name + role required")
	}
	if !validLayoutRole(role) {
		return uuid.Nil, errors.New("dashboards: unsupported role")
	}
	body, _ := json.Marshal(widgets)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	if isDefault {
		if _, err := tx.Exec(ctx, `
			UPDATE user_dashboard_layouts SET is_default=false
			 WHERE user_id=$1 AND role=$2 AND is_default=true`, userID, role); err != nil {
			return uuid.Nil, err
		}
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO user_dashboard_layouts(user_id, tenant_id, name, role, is_default, widgets)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		ON CONFLICT (user_id, name) DO UPDATE
		   SET widgets    = EXCLUDED.widgets,
		       role       = EXCLUDED.role,
		       is_default = EXCLUDED.is_default,
		       updated_at = now()
		RETURNING id`,
		userID, tenantID, name, role, isDefault, body).Scan(&id)
	if err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

func (s *Service) DefaultLayout(ctx context.Context, userID uuid.UUID, role string) (*Layout, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id, name, role, is_default, widgets, updated_at
		  FROM user_dashboard_layouts
		 WHERE user_id=$1 AND role=$2 AND is_default=true
		 LIMIT 1`, userID, role)
	return scanLayout(row.Scan)
}

func (s *Service) ListLayouts(ctx context.Context, userID uuid.UUID) ([]Layout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, tenant_id, name, role, is_default, widgets, updated_at
		  FROM user_dashboard_layouts
		 WHERE user_id=$1 ORDER BY role, name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Layout
	for rows.Next() {
		l, err := scanLayout(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}

func scanLayout(scan func(...any) error) (*Layout, error) {
	var l Layout
	var widgetsRaw []byte
	if err := scan(&l.ID, &l.UserID, &l.TenantID, &l.Name, &l.Role, &l.IsDefault,
		&widgetsRaw, &l.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(widgetsRaw, &l.Widgets)
	return &l, nil
}

func validLayoutRole(r string) bool {
	switch r {
	case "executive", "soc", "risk", "partner_msp", "scope_admin":
		return true
	}
	return false
}

// ----- Geo scan map ---------------------------------------------------------

type GeoNode struct {
	NodeID    uuid.UUID `json:"node_id"`
	Region    string    `json:"region"`
	Hostname  string    `json:"hostname"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	Status    string    `json:"status"`
	Inflight  int       `json:"inflight"`
	LastHeart time.Time `json:"last_heartbeat,omitempty"`
}

// GeoNodes returns every scanner node with its coords + live load. Used
// by the geo scan map widget on the executive dashboard.
func (s *Service) GeoNodes(ctx context.Context) ([]GeoNode, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.region, r.hostname,
		       COALESCE(r.latitude, 0), COALESCE(r.longitude, 0),
		       COALESCE(r.city,''), COALESCE(r.country,''), r.status,
		       COALESCE(h.inflight_jobs, 0),
		       COALESCE(h.last_heartbeat_at, r.last_heartbeat)
		  FROM scanner_node_registry r
		  LEFT JOIN scanner_node_health h ON h.node_id = r.id
		 WHERE r.latitude IS NOT NULL AND r.longitude IS NOT NULL
		 ORDER BY r.region`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoNode
	for rows.Next() {
		var g GeoNode
		var hb *time.Time
		if err := rows.Scan(&g.NodeID, &g.Region, &g.Hostname,
			&g.Latitude, &g.Longitude, &g.City, &g.Country, &g.Status,
			&g.Inflight, &hb); err != nil {
			return nil, err
		}
		if hb != nil {
			g.LastHeart = *hb
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ----- Compliance dashboard --------------------------------------------------

type ComplianceSnapshot struct {
	Framework        string             `json:"framework"`
	FrameworkVersion string             `json:"framework_version"`
	ControlsTotal    int                `json:"controls_total"`
	ControlsAtRisk   int                `json:"controls_at_risk"`
	BySeverity       map[string]int     `json:"by_severity"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// ComplianceForTenant counts how many findings (open severity > info) each
// framework's controls would flag for a tenant. Used by the compliance
// dashboard summary tile.
func (s *Service) ComplianceForTenant(ctx context.Context, tenantID uuid.UUID) ([]ComplianceSnapshot, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT framework, framework_version FROM compliance_controls
		 ORDER BY framework, framework_version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snaps []ComplianceSnapshot
	for rows.Next() {
		var snap ComplianceSnapshot
		if err := rows.Scan(&snap.Framework, &snap.FrameworkVersion); err != nil {
			return nil, err
		}
		snap.BySeverity = map[string]int{}
		snap.UpdatedAt = time.Now().UTC()
		snaps = append(snaps, snap)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// For each framework, count controls + at-risk + per-severity findings.
	for i, sn := range snaps {
		_ = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM compliance_controls
			 WHERE framework=$1 AND framework_version=$2`,
			sn.Framework, sn.FrameworkVersion).Scan(&snaps[i].ControlsTotal)

		var atRisk int
		_ = s.pool.QueryRow(ctx, `
			SELECT COUNT(DISTINCT c.id)
			  FROM compliance_controls c, findings f,
			       jsonb_array_elements_text(c.finding_patterns) p(pattern)
			 WHERE c.framework=$1 AND c.framework_version=$2
			   AND f.tenant_id=$3 AND f.status NOT IN ('closed','remediated','retest_passed','false_positive')
			   AND f.title ~* p.pattern`,
			sn.Framework, sn.FrameworkVersion, tenantID).Scan(&atRisk)
		snaps[i].ControlsAtRisk = atRisk

		sevRows, err := s.pool.Query(ctx, `
			SELECT f.severity, COUNT(DISTINCT f.id)
			  FROM compliance_controls c, findings f,
			       jsonb_array_elements_text(c.finding_patterns) p(pattern)
			 WHERE c.framework=$1 AND c.framework_version=$2
			   AND f.tenant_id=$3 AND f.title ~* p.pattern
			   AND f.status NOT IN ('closed','remediated','retest_passed','false_positive')
			 GROUP BY f.severity`,
			sn.Framework, sn.FrameworkVersion, tenantID)
		if err != nil {
			return nil, err
		}
		for sevRows.Next() {
			var sev string
			var n int
			if err := sevRows.Scan(&sev, &n); err != nil {
				sevRows.Close()
				return nil, err
			}
			snaps[i].BySeverity[sev] = n
		}
		sevRows.Close()
	}
	return snaps, nil
}

// ----- SSE live-update channel ----------------------------------------------

// LiveStream is an in-process pub/sub the API binds to its
// /api/v1/dashboards/stream SSE endpoint. The integrations Wire pattern
// already pushes bus events into in-process channels; LiveStream adds a
// per-tenant filtered fanout that the dashboard widgets subscribe to.
type LiveStream struct {
	mu       sync.RWMutex
	subs     map[uuid.UUID]*subscriber
	bus      *eventbus.Bus
}

type subscriber struct {
	id       uuid.UUID
	tenantID uuid.UUID
	channel  string
	C        chan LiveMessage
	// delivered / dropped counted via atomic.Add. Snapshotted on
	// stream close and recorded in dashboard_sse_subscriptions so
	// ops can see per-stream loss after the fact.
	delivered uint64
	dropped   uint64
}

type LiveMessage struct {
	Type    string    `json:"type"`
	Tenant  uuid.UUID `json:"tenant_id"`
	Time    time.Time `json:"time"`
	Payload map[string]any `json:"payload,omitempty"`
}

func NewLiveStream(bus *eventbus.Bus) *LiveStream {
	ls := &LiveStream{
		subs: map[uuid.UUID]*subscriber{},
		bus:  bus,
	}
	// Subscribe to every event type — fan out matching events to
	// per-tenant channels.
	for _, et := range eventbus.AllEventTypes() {
		eventType := et
		bus.Subscribe(eventType, func(_ context.Context, ev eventbus.Event) {
			ls.dispatch(eventType, ev)
		})
	}
	return ls
}

func (ls *LiveStream) dispatch(eventType string, ev eventbus.Event) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	for _, s := range ls.subs {
		if ev.TenantID != nil && s.tenantID != *ev.TenantID {
			continue
		}
		msg := LiveMessage{
			Type: eventType, Tenant: tenantOrZero(ev.TenantID), Time: time.Now().UTC(),
			Payload: ev.Payload,
		}
		// Non-blocking send: a slow SSE consumer (browser tab tucked
		// in a background window, idle laptop lid closed) drops
		// events rather than stalling the dispatcher across every
		// other subscriber. The trade-off is that compliance-critical
		// channels CANNOT rely on the SSE stream alone — they must
		// also be persisted (audit_logs / findings tables) and
		// reconciled on reconnect. We track drops so ops can alert
		// when a subscriber starts losing events.
		select {
		case s.C <- msg:
			atomic.AddUint64(&s.delivered, 1)
		default:
			atomic.AddUint64(&s.dropped, 1)
			if liveStreamDropSink != nil {
				liveStreamDropSink(eventType)
			}
		}
	}
}

// liveStreamDropSink lets cmd/api wire a Prometheus counter without
// the dashboards package importing observability (which would form
// a cycle via audit). Nil = no metric, just per-subscriber atomic
// counters that the SSE endpoint can expose on close.
var liveStreamDropSink func(eventType string)

// SetDropSink wires a callback fired once per dropped SSE message.
// cmd/api binds this to observability.DashboardSSEDrops.WithLabelValues.
func SetDropSink(f func(eventType string)) { liveStreamDropSink = f }

func tenantOrZero(t *uuid.UUID) uuid.UUID {
	if t == nil {
		return uuid.Nil
	}
	return *t
}

// Subscribe registers a consumer and writes a DB row so an operator can
// see open SSE streams. Returns a closer the caller must defer.
func (ls *LiveStream) Subscribe(ctx context.Context, pool *pgxpool.Pool, userID, tenantID uuid.UUID, channel string) (chan LiveMessage, func(), error) {
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO dashboard_sse_subscriptions(id, user_id, tenant_id, channel)
		VALUES ($1, $2, $3, $4)`, id, userID, tenantID, channel); err != nil {
		return nil, nil, err
	}
	s := &subscriber{
		id: id, tenantID: tenantID, channel: channel,
		C: make(chan LiveMessage, 64),
	}
	ls.mu.Lock()
	ls.subs[id] = s
	ls.mu.Unlock()
	var closeOnce sync.Once
	closer := func() {
		closeOnce.Do(func() {
			ls.mu.Lock()
			delete(ls.subs, id)
			ls.mu.Unlock()
			close(s.C)
			// Cleanup runs after the request ctx is dead. Use a
			// fresh ctx with a bound so a DB stall can't keep
			// this goroutine alive past the brief teardown
			// window.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = pool.Exec(ctx,
				`UPDATE dashboard_sse_subscriptions SET closed_at=now() WHERE id=$1`, id)
		})
	}
	return s.C, closer, nil
}

// ActiveCount returns the number of open SSE streams. Used by the
// operator-only "live consumers" tile.
func (ls *LiveStream) ActiveCount() int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return len(ls.subs)
}

