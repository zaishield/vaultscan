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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
)

type Service struct {
	pool   *pgxpool.Pool
	bus    *eventbus.Bus
	audit  *audit.Service
	client *http.Client
}

func New(pool *pgxpool.Pool, bus *eventbus.Bus, a *audit.Service) *Service {
	return &Service{pool: pool, bus: bus, audit: a, client: &http.Client{Timeout: 10 * time.Second}}
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
		out = append(out, it)
	}
	return out, rows.Err()
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

// Wire subscribes the integration service to every event in eventbus.AllEventTypes
// and dispatches matching deliveries to enabled integrations.
func (s *Service) Wire(bus *eventbus.Bus) {
	for _, et := range eventbus.AllEventTypes() {
		bus.Subscribe(et, func(ctx context.Context, ev eventbus.Event) {
			s.fanout(context.Background(), ev)
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
		go s.deliver(context.Background(), id, itype, name, config, ev)
	}
}

func (s *Service) deliver(ctx context.Context, integrationID uuid.UUID, itype, name string,
	config map[string]any, ev eventbus.Event) {
	body, err := s.buildPayload(itype, name, ev)
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
	attempt := 0
	delay := 1 * time.Second
	for attempt < 5 {
		attempt++
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			s.recordDelivery(ctx, integrationID, ev, attempt, "failed", 0, err.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if secret, ok := config["hmac_secret"].(string); ok {
			req.Header.Set("X-Vaultscan-Signature",
				"sha256="+hexDigest(hmac.New(sha256.New, []byte(secret)), body))
		}
		resp, err := s.client.Do(req)
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
		time.Sleep(delay)
		delay *= 2
	}
	s.recordDelivery(ctx, integrationID, ev, attempt, "failed", 0, "max attempts reached")
}

// buildPayload formats the event for the destination type. We keep payload
// shape pragmatic: Slack/Teams use text; others receive a structured envelope.
func (s *Service) buildPayload(itype, name string, ev eventbus.Event) ([]byte, error) {
	switch itype {
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
	default:
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

var _ = errors.New
