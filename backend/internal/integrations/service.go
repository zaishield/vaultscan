// Package integrations is the outbound bridge to ticketing, chat, SIEM, and
// DevSecOps systems (Blueprint §31). Each delivery is retried with
// exponential backoff and recorded in integration_deliveries.
package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/circuitbreaker"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/observability"
)

type Service struct {
	pool   *pgxpool.Pool
	bus    *eventbus.Bus
	audit  *audit.Service
	client *http.Client

	// OutboundWrapper is the vault-backed unwrap helper used to
	// retrieve the outbound HMAC signing secret from the
	// integrations.outbound_hmac_secret_encrypted column (migration
	// 0069). Set this from cmd/api/main.go to s.Vault so Test/Send
	// can decrypt the secret. nil = legacy-only mode (config.hmac_secret
	// JSONB path).
	OutboundWrapper interface {
		UnwrapBlob(ctx context.Context, blob []byte) ([]byte, error)
	}

	// MaxAttempts is the maximum total deliveries (incl. the initial one)
	// before an event is parked in the DLQ. Production default 5; tests
	// can lower it to keep the suite snappy.
	MaxAttempts int
	// InitialBackoff is the wait before the second attempt. Each
	// subsequent attempt doubles the wait. Default 1s.
	InitialBackoff time.Duration

	// pool is the worker pool used by the bus-fanout path. nil → falls
	// back to legacy `go s.deliver(...)` (single-pod dev only).
	workerPool *WorkerPool

	// Per-integration circuit breakers. When a single upstream
	// (Jira / Slack / a specific webhook URL) flaps, the breaker
	// trips after MaxFailures consecutive failures and short-
	// circuits subsequent attempts with ErrBreakerOpen — so the
	// worker pool stops burning retries against a known-dead
	// upstream. Keyed by integration_id so two integrations to
	// the same provider type are isolated.
	breakersMu sync.RWMutex
	breakers   map[uuid.UUID]*circuitbreaker.Breaker
}

// AttachWorkerPool installs a bounded worker pool on the service.
// fanout will Submit() jobs to the pool; if the pool is full the job
// is delivered inline (best-effort backpressure).
func (s *Service) AttachWorkerPool(p *WorkerPool) {
	s.workerPool = p
}

func New(pool *pgxpool.Pool, bus *eventbus.Bus, a *audit.Service) *Service {
	return &Service{
		pool: pool, bus: bus, audit: a,
		// SSRF-guarded transport: the dialer.Control callback rejects
		// any connection attempt whose post-resolution IP is in the
		// blocked-CIDR list (cloud metadata, RFC1918, loopback, link-
		// local, IPv6 ULA). The pre-flight validateOutboundURL call
		// in deliver/test catches the obvious cases earlier with a
		// cleaner error.
		client:         &http.Client{Timeout: 10 * time.Second, Transport: newSafeTransport()},
		MaxAttempts:    5,
		InitialBackoff: time.Second,
		breakers:       map[uuid.UUID]*circuitbreaker.Breaker{},
	}
}

// SupportedTypes lists the integration kinds the platform can wire up.
func SupportedTypes() []string {
	return []string{
		"jira", "servicenow", "slack", "teams", "webhook",
		"siem", "gitlab", "github", "jenkins", "sentinel",
	}
}

type CreateInput struct {
	TenantID    *uuid.UUID
	PartnerID   *uuid.UUID
	Type        string
	Name        string
	Config      map[string]any
	SecretRef   string  // pointer into secrets store; never plaintext
	EventFilter []string
	CreatedBy   *uuid.UUID
}

func (s *Service) Create(ctx context.Context, in CreateInput) (uuid.UUID, error) {
	if !validType(in.Type) {
		return uuid.Nil, fmt.Errorf("integrations: unsupported type %q", in.Type)
	}
	id := uuid.New()
	cfg, _ := json.Marshal(in.Config)
	flt, _ := json.Marshal(in.EventFilter)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO integrations(id, tenant_id, partner_id, type, name, enabled,
		    config, secret_ref, event_filter, created_by)
		VALUES ($1,$2,$3,$4,$5,true,$6::jsonb, $7, $8::jsonb, $9)`,
		id, in.TenantID, in.PartnerID, in.Type, in.Name, cfg, in.SecretRef, flt, in.CreatedBy); err != nil {
		return uuid.Nil, err
	}
	platID := uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: platID, PartnerID: in.PartnerID, TenantID: in.TenantID, ActorID: in.CreatedBy,
		Event: audit.EventIntegrationCreated, TargetType: "integration", TargetID: id.String(),
		Payload: map[string]any{"type": in.Type, "name": in.Name},
	})
	return id, nil
}

func (s *Service) List(ctx context.Context, tenantID *uuid.UUID, partnerID *uuid.UUID) ([]Integration, error) {
	args := []any{}
	q := `SELECT id, tenant_id, partner_id, type, name, enabled, config, event_filter,
	             COALESCE(last_status,''), last_check_at, created_at
	        FROM integrations WHERE 1=1`
	if tenantID != nil {
		q += fmt.Sprintf(" AND tenant_id=$%d", len(args)+1)
		args = append(args, *tenantID)
	}
	if partnerID != nil {
		q += fmt.Sprintf(" AND partner_id=$%d", len(args)+1)
		args = append(args, *partnerID)
	}
	q += " ORDER BY created_at DESC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Integration
	for rows.Next() {
		var it Integration
		var cfg, flt []byte
		if err := rows.Scan(&it.ID, &it.TenantID, &it.PartnerID, &it.Type, &it.Name, &it.Enabled,
			&cfg, &flt, &it.LastStatus, &it.LastCheckAt, &it.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cfg, &it.Config)
		_ = json.Unmarshal(flt, &it.EventFilter)
		// Redact secret-like config keys so a manage_integrations
		// LIST doesn't surface live secrets to anyone with the role.
		// The Test() path that actually NEEDS the secret reads from
		// the DB directly via getOutboundSecret rather than this view.
		redactSecretConfig(it.Config)
		out = append(out, it)
	}
	return out, rows.Err()
}

// redactSecretConfig replaces sensitive-looking values with a
// fixed placeholder so callers of List() can't accidentally
// surface them to the wire. The Test/Send paths that need the
// real value read fresh from the DB.
func redactSecretConfig(cfg map[string]any) {
	for _, key := range []string{
		"hmac_secret", "api_key", "auth_token", "password",
		"client_secret", "bearer_token", "webhook_secret",
	} {
		if _, ok := cfg[key]; ok {
			cfg[key] = "[REDACTED]"
		}
	}
}

type Integration struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	PartnerID   *uuid.UUID `json:"partner_id,omitempty"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Enabled     bool       `json:"enabled"`
	Config      map[string]any `json:"config"`
	EventFilter []string   `json:"event_filter"`
	LastStatus  string     `json:"last_status"`
	LastCheckAt *time.Time `json:"last_check_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Test dispatches a single synthetic payload to the integration's
// destination URL and reports back whether the endpoint accepted it.
// Used by the portal's "Test Connection" button so operators can verify
// a Slack / Jira / webhook is reachable + the credentials work, without
// waiting for a real event.
type TestResult struct {
	OK           bool   `json:"ok"`
	StatusCode   int    `json:"status_code"`
	LatencyMs    int    `json:"latency_ms"`
	ResponseBody string `json:"response_body,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (s *Service) Test(ctx context.Context, integrationID uuid.UUID) (*TestResult, error) {
	var (
		itype string
		cfg   []byte
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT type, config FROM integrations WHERE id=$1`, integrationID).
		Scan(&itype, &cfg); err != nil {
		return nil, fmt.Errorf("integrations: load: %w", err)
	}
	var config map[string]any
	_ = json.Unmarshal(cfg, &config)

	target, _ := config["url"].(string)
	if target == "" {
		target, _ = config["api_url"].(string)
	}
	if target == "" {
		return &TestResult{Error: "no url / api_url configured"}, nil
	}
	// SSRF guard. validateOutboundURL pre-resolves the host and
	// refuses any URL whose resolution lands in a blocked CIDR.
	// The transport-level dialer guard catches DNS-rebinding races.
	if _, err := validateOutboundURL(target); err != nil {
		return &TestResult{Error: err.Error()}, nil
	}
	body, _ := json.Marshal(map[string]any{
		"event_type": "vaultscan.test",
		"message":    "VAULTSCAN connection test from /api/v1/integrations/" + integrationID.String() + "/test",
		"integration_type": itype,
	})
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return &TestResult{Error: err.Error()}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	// Prefer the encrypted-at-rest secret (migration 0069); fall
	// back to legacy plaintext config["hmac_secret"] for un-migrated
	// integrations. SetOutboundHMACSecret moves a tenant to the
	// encrypted form on the next operator edit.
	if secret, _ := s.outboundHMACSecret(ctx, integrationID, s.OutboundWrapper); secret != "" {
		req.Header.Set("X-Vaultscan-Signature",
			"sha256="+hexDigest(hmac.New(sha256.New, []byte(secret)), body))
	} else if legacy, ok := config["hmac_secret"].(string); ok && legacy != "" {
		req.Header.Set("X-Vaultscan-Signature",
			"sha256="+hexDigest(hmac.New(sha256.New, []byte(legacy)), body))
	}
	resp, err := s.client.Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return &TestResult{Error: err.Error(), LatencyMs: latency}, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := &TestResult{
		OK:           resp.StatusCode < 400,
		StatusCode:   resp.StatusCode,
		LatencyMs:    latency,
		ResponseBody: string(respBody),
	}
	// Persist the test outcome so the health view doesn't have to repeat it.
	_, _ = s.pool.Exec(ctx, `
		UPDATE integrations SET last_status=$2, last_check_at=now() WHERE id=$1`,
		integrationID, statusLabel(res))
	return res, nil
}

// Health is one row in the integration health dashboard view.
type Health struct {
	IntegrationID    uuid.UUID `json:"integration_id"`
	Type             string    `json:"type"`
	Name             string    `json:"name"`
	Enabled          bool      `json:"enabled"`
	Last5MinDelivered int      `json:"last_5min_delivered"`
	Last5MinFailed    int      `json:"last_5min_failed"`
	LastStatus        string   `json:"last_status"`
}

// HealthRollup returns one row per integration with delivery success/fail
// counts for the last 5 minutes, plus the latest test status.
func (s *Service) HealthRollup(ctx context.Context, tenantID, partnerID *uuid.UUID) ([]Health, error) {
	args := []any{}
	q := `SELECT i.id, i.type, i.name, i.enabled,
	             COALESCE(i.last_status, ''),
	             COUNT(d.id) FILTER (WHERE d.status='delivered' AND d.created_at > now() - INTERVAL '5 minutes'),
	             COUNT(d.id) FILTER (WHERE d.status='failed'    AND d.created_at > now() - INTERVAL '5 minutes')
	        FROM integrations i
	   LEFT JOIN integration_deliveries d ON d.integration_id = i.id
	       WHERE 1=1`
	if tenantID != nil {
		q += fmt.Sprintf(" AND i.tenant_id=$%d", len(args)+1)
		args = append(args, *tenantID)
	}
	if partnerID != nil {
		q += fmt.Sprintf(" AND i.partner_id=$%d", len(args)+1)
		args = append(args, *partnerID)
	}
	q += " GROUP BY i.id ORDER BY i.created_at DESC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Health
	for rows.Next() {
		var h Health
		if err := rows.Scan(&h.IntegrationID, &h.Type, &h.Name, &h.Enabled,
			&h.LastStatus, &h.Last5MinDelivered, &h.Last5MinFailed); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func statusLabel(r *TestResult) string {
	if r.OK {
		return fmt.Sprintf("test ok %d", r.StatusCode)
	}
	if r.Error != "" {
		return "test error: " + r.Error
	}
	return fmt.Sprintf("test fail %d", r.StatusCode)
}

// Wire subscribes the integration service to every event in eventbus.AllEventTypes
// and dispatches matching deliveries to enabled integrations. The
// caller-provided context is propagated to the bus subscription so
// shutdown cancels in-flight queries.
func (s *Service) Wire(bus *eventbus.Bus) {
	for _, et := range eventbus.AllEventTypes() {
		bus.Subscribe(et, func(ctx context.Context, ev eventbus.Event) {
			s.fanout(ctx, ev)
		})
	}
}

func (s *Service) fanout(ctx context.Context, ev eventbus.Event) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, type, name, config, event_filter
		  FROM integrations
		 WHERE enabled=true
		   AND (tenant_id IS NULL OR tenant_id=$1)
		   AND (partner_id IS NULL OR partner_id=$2)`, ev.TenantID, ev.PartnerID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id          uuid.UUID
			itype, name string
			cfg, flt    []byte
		)
		if err := rows.Scan(&id, &itype, &name, &cfg, &flt); err != nil {
			continue
		}
		var filter []string
		_ = json.Unmarshal(flt, &filter)
		if len(filter) > 0 && !contains(filter, ev.Type) {
			continue
		}
		var config map[string]any
		_ = json.Unmarshal(cfg, &config)
		job := DeliveryJob{
			IntegrationID: id, Type: itype, Name: name,
			Config: config, Event: ev,
		}
		// Prefer the bounded pool. If unavailable or saturated, fall
		// back to inline delivery (synchronously) so the caller
		// experiences backpressure rather than an unbounded goroutine
		// fan-out.
		if s.workerPool != nil {
			if s.workerPool.Submit(job) {
				continue
			}
		}
		// Backpressure path: deliver synchronously in the bus subscriber's
		// goroutine. The bus already runs subscribers in their own
		// goroutines so this doesn't pin the publisher.
		s.deliver(ctx, id, itype, name, config, ev)
	}
}

func (s *Service) deliver(ctx context.Context, integrationID uuid.UUID, itype, name string,
	config map[string]any, ev eventbus.Event) {
	var err error
	ctx, end := observability.Span(ctx, "integrations.deliver",
		"integration_id", integrationID.String(),
		"type", itype,
		"event_type", string(ev.Type))
	defer func() { end(err) }()

	body, err := s.buildPayload(ctx, itype, name, ev)
	if err != nil {
		return
	}
	target, ok := config["url"].(string)
	if !ok && itype != "jira" && itype != "servicenow" {
		// jira/servicenow could use api_url; everything else needs a URL.
		s.recordDelivery(ctx, integrationID, ev, 1, "failed", 0, "no url configured")
		return
	}
	if target == "" {
		if api, ok := config["api_url"].(string); ok {
			target = api
		}
	}
	// SSRF guard at dispatch time. A misconfigured / malicious
	// integration target gets a 'ssrf_blocked' delivery error and
	// the event lands in dead-letters for operator review, rather
	// than the cluster making an outbound call to a metadata service
	// or internal admin port.
	if _, err := validateOutboundURL(target); err != nil {
		s.recordDelivery(ctx, integrationID, ev, 1, "failed", 0, err.Error())
		return
	}
	attempt := 0
	delay := s.InitialBackoff
	if delay <= 0 {
		delay = time.Second
	}
	maxAttempts := s.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	for attempt < maxAttempts {
		attempt++
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			s.recordDelivery(ctx, integrationID, ev, attempt, "failed", 0, err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")
		// See Test() for the same encrypted-preferred lookup.
		if secret, _ := s.outboundHMACSecret(ctx, integrationID, s.OutboundWrapper); secret != "" {
			req.Header.Set("X-Vaultscan-Signature",
				"sha256="+hexDigest(hmac.New(sha256.New, []byte(secret)), body))
		} else if legacy, ok := config["hmac_secret"].(string); ok && legacy != "" {
			req.Header.Set("X-Vaultscan-Signature",
				"sha256="+hexDigest(hmac.New(sha256.New, []byte(legacy)), body))
		}
		// Wrap the actual upstream call in the per-integration
		// circuit breaker. When the breaker is open the call
		// returns ErrBreakerOpen immediately — counted as a
		// failure attempt so the existing backoff still applies,
		// but no socket gets opened to a known-dead upstream.
		var resp *http.Response
		breaker := s.breakerFor(integrationID, itype)
		breakerErr := breaker.Call(func() error {
			var derr error
			resp, derr = s.client.Do(req)
			if derr != nil {
				return derr
			}
			// Treat 5xx as failure so the breaker actually
			// tracks upstream health (4xx is a client-side
			// problem; opening the breaker for 400s would punish
			// our own bad payloads).
			if resp.StatusCode >= 500 {
				return fmt.Errorf("upstream %d", resp.StatusCode)
			}
			return nil
		})
		err = breakerErr
		if err == nil {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode < 400 {
				s.recordDelivery(ctx, integrationID, ev, attempt, "delivered", resp.StatusCode, string(respBody))
				return
			}
			s.recordDelivery(ctx, integrationID, ev, attempt, "retrying", resp.StatusCode, string(respBody))
		} else {
			s.recordDelivery(ctx, integrationID, ev, attempt, "retrying", 0, err.Error())
		}
		// ctx-aware sleep so worker-pool shutdown can interrupt the
		// retry loop without waiting for the full backoff. Without
		// this, a 16s exponential backoff at attempt 4 would hold up
		// the pool's Stop() call for that whole duration.
		//
		// Jitter the backoff in [0.5×, 1.5×] of the nominal value so
		// a flapping upstream doesn't synchronise every worker's
		// retry into a thundering herd. Without jitter, N workers
		// that all failed at T see their second attempts land at
		// roughly T+delay all at once.
		jittered := jitterDuration(delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(jittered):
		}
		delay *= 2
		// Cap the backoff so attempt 6+ doesn't sit on a 60-minute
		// timer holding open connection state. The integration is
		// allowed at most ~5 minutes between attempts; if the
		// upstream is still failing past that, DLQ is the better
		// destination than an indefinite back-off.
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
	}
	s.recordDelivery(ctx, integrationID, ev, attempt, "failed", 0, "max attempts reached")
	observability.IntegrationDeliveryFailures.WithLabelValues(itype).Inc()
	// VS-11: send the event to the dead-letter queue so an operator can
	// inspect + replay later. We pull the last status row to capture the
	// final HTTP code (if any).
	var lastCode *int
	var lastErr string
	_ = s.pool.QueryRow(ctx, `
		SELECT response_code, COALESCE(response_body,'')
		  FROM integration_deliveries
		 WHERE integration_id=$1 AND event_id=$2
		 ORDER BY created_at DESC LIMIT 1`,
		integrationID, ev.ID).Scan(&lastCode, &lastErr)
	code := 0
	if lastCode != nil {
		code = *lastCode
	}
	_, _ = s.EnqueueDeadLetter(ctx, integrationID, ev, attempt, lastErr, code)
}

// buildPayload formats the event for the destination type. We keep payload
// shape pragmatic: Slack/Teams use text; SIEM uses CEF/LEEF; Jira/ServiceNow
// produce typed tickets; others receive a structured envelope.
func (s *Service) buildPayload(ctx context.Context, itype, name string, ev eventbus.Event) ([]byte, error) {
	switch itype {
	case "jira":
		issueType, _ := s.integrationField(ctx, name, "issue_type")
		config, _ := s.integrationConfig(ctx, name)
		return BuildJiraIssue(ev, config, issueType)
	case "servicenow":
		config, _ := s.integrationConfig(ctx, name)
		return BuildServiceNowIncident(ev, config)
	case "siem":
		format, _ := s.integrationField(ctx, name, "format")
		switch strings.ToLower(format) {
		case "cef":
			return []byte(BuildCEF(ev)), nil
		case "leef":
			return []byte(BuildLEEF(ev)), nil
		}
	case "slack":
		return json.Marshal(map[string]any{
			"text": fmt.Sprintf("[%s] VAULTSCAN event %s", strings.ToUpper(ev.Type), ev.ID),
			"blocks": []map[string]any{
				{"type": "section", "text": map[string]any{"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n```%s```", ev.Type, jsonString(ev.Payload))}},
			},
		})
	case "teams":
		return json.Marshal(map[string]any{
			"@type": "MessageCard", "@context": "https://schema.org/extensions",
			"summary": "VAULTSCAN event", "themeColor": "0F172A",
			"title": ev.Type,
			"text":  jsonString(ev.Payload),
		})
	}
	return json.Marshal(map[string]any{
		"event_id":   ev.ID,
		"event_type": ev.Type,
		"tenant_id":  ev.TenantID,
		"partner_id": ev.PartnerID,
		"actor_id":   ev.ActorID,
		"payload":    ev.Payload,
		"emitted_by": "vaultscan",
	})
}

func (s *Service) recordDelivery(ctx context.Context, integrationID uuid.UUID, ev eventbus.Event,
	attempt int, status string, code int, body string) {
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO integration_deliveries(integration_id, event_id, event_type, attempt,
		    status, response_code, response_body, delivered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,
		        CASE WHEN $5='delivered' THEN now() ELSE NULL END)`,
		integrationID, ev.ID, ev.Type, attempt, status,
		nullIfZero(code), nullIfEmpty(body))
}

// integrationField pulls a single string column off the integration
// row by name. The `field` argument must be one of the columns in
// the allowed-fields whitelist below — every other value is refused
// at runtime so a future caller that accepts a user-supplied field
// can't smuggle SQL through the identifier interpolation. The body
// of the query is parameterised normally; this whitelist is the
// defence against identifier injection.
func (s *Service) integrationField(ctx context.Context, name, field string) (string, error) {
	if !allowedIntegrationFields[field] {
		return "", fmt.Errorf("integrations: field %q is not allow-listed", field)
	}
	var v *string
	if err := s.pool.QueryRow(ctx,
		// #nosec G201 — field has been whitelisted just above.
		`SELECT `+field+` FROM integrations WHERE name=$1 LIMIT 1`, name).Scan(&v); err != nil {
		return "", err
	}
	if v == nil {
		return "", nil
	}
	return *v, nil
}

// allowedIntegrationFields enumerates every column integrationField()
// is permitted to read. Adding a new field is a deliberate edit
// here, not a behavioural change at the call site.
var allowedIntegrationFields = map[string]bool{
	"issue_type": true,
	"format":     true,
	"name":       true,
	"type":       true,
	"endpoint":   true,
}

func (s *Service) integrationConfig(ctx context.Context, name string) (map[string]any, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT config FROM integrations WHERE name=$1 LIMIT 1`, name).Scan(&raw); err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func validType(t string) bool {
	for _, v := range SupportedTypes() {
		if v == t {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func hexDigest(h interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, body []byte) string {
	_, _ = h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// jitterDuration returns d scaled by a uniform random factor in
// [0.5, 1.5]. Used by the delivery retry loop to spread thundering
// herds across the pool when an upstream flaps.
func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	factor := 0.5 + rand.Float64() // [0.5, 1.5)
	return time.Duration(float64(d) * factor)
}

// breakerFor returns the lazily-created circuit breaker for an
// integration. One breaker per integration_id (not per type), so
// two distinct Slack webhooks fail independently. MaxFailures=5,
// Cooldown=30s — production-default values matching the
// circuitbreaker package's own defaults.
func (s *Service) breakerFor(integrationID uuid.UUID, name string) *circuitbreaker.Breaker {
	s.breakersMu.RLock()
	b, ok := s.breakers[integrationID]
	s.breakersMu.RUnlock()
	if ok {
		return b
	}
	s.breakersMu.Lock()
	defer s.breakersMu.Unlock()
	// Re-check under the write lock; another goroutine may have
	// created the breaker between our RLock and Lock.
	if b, ok = s.breakers[integrationID]; ok {
		return b
	}
	b = circuitbreaker.New(circuitbreaker.Config{Name: name})
	s.breakers[integrationID] = b
	return b
}
