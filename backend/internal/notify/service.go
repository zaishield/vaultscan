// Package notify is the §23 outbound delivery surface — one queue, one
// dispatch loop, three production channels (SMTP, Twilio SMS, PagerDuty
// Events v2). The email/* package already renders partner-branded
// templates; this package owns the actual ship-it-and-retry logic.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool  *pgxpool.Pool

	// Per-channel transports. Wired at boot by the API binary; the
	// cron-runner's dispatch loop picks them up via the same pool.
	transports map[string]Transport
}

// Transport is the contract every adapter satisfies.
type Transport interface {
	Kind() string
	Send(ctx context.Context, channel ChannelConfig, msg Message) (response string, err error)
}

type ChannelConfig struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Kind      string
	Label     string
	Config    map[string]any
	SecretRef string
}

type Message struct {
	Subject  string
	Body     string
	Priority string                 // low | normal | high | urgent
	Payload  map[string]any
}

func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, transports: map[string]Transport{}}
}

// RegisterTransport wires one channel adapter. cmd/api/main.go calls
// once per channel: smtp, twilio, pagerduty.
func (s *Service) RegisterTransport(t Transport) {
	s.transports[t.Kind()] = t
}

// CreateChannel adds a tenant-scoped delivery channel.
func (s *Service) CreateChannel(ctx context.Context, in ChannelConfig) (uuid.UUID, error) {
	if in.Kind == "" || in.Label == "" {
		return uuid.Nil, errors.New("notify: channel kind + label required")
	}
	cfgJSON, _ := json.Marshal(in.Config)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO notification_channels(tenant_id, kind, label, config, secret_ref)
		VALUES ($1, $2, $3, $4::jsonb, NULLIF($5,''))
		ON CONFLICT (tenant_id, label) DO UPDATE
		   SET config = EXCLUDED.config,
		       secret_ref = EXCLUDED.secret_ref,
		       kind = EXCLUDED.kind
		RETURNING id`,
		in.TenantID, in.Kind, in.Label, cfgJSON, in.SecretRef).Scan(&id)
	return id, err
}

// Enqueue inserts a row for the next dispatch tick.
type EnqueueInput struct {
	ChannelID uuid.UUID
	Subject   string
	Body      string
	Priority  string
	Payload   map[string]any
}

func (s *Service) Enqueue(ctx context.Context, in EnqueueInput) (uuid.UUID, error) {
	if in.Priority == "" {
		in.Priority = "normal"
	}
	payJSON, _ := json.Marshal(in.Payload)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO notification_queue(channel_id, subject, body, priority, payload)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id`,
		in.ChannelID, in.Subject, in.Body, in.Priority, payJSON).Scan(&id)
	return id, err
}

// DispatchOne pulls the oldest due row, hands it to the appropriate
// transport, marks the result. The cron-runner calls this in a loop.
// Returns true if a message was processed (so the caller can keep
// looping until false → no more work).
func (s *Service) DispatchOne(ctx context.Context) (processed bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var (
		msgID, channelID                uuid.UUID
		subject, body, priority         string
		attempt                         int
		payloadRaw                      []byte
		kind, label, secretRef          string
		cfgRaw                          []byte
		tenantID                        uuid.UUID
	)
	err = tx.QueryRow(ctx, `
		SELECT q.id, q.channel_id, q.subject, q.body, q.priority, q.attempt,
		       q.payload, c.tenant_id, c.kind, c.label, COALESCE(c.secret_ref,''),
		       c.config
		  FROM notification_queue q
		  JOIN notification_channels c ON c.id = q.channel_id
		 WHERE q.state IN ('pending','failed')
		   AND q.next_attempt_at <= now()
		   AND c.enabled = true
		 ORDER BY q.priority='urgent' DESC, q.priority='high' DESC, q.next_attempt_at ASC
		 LIMIT 1
		 FOR UPDATE OF q SKIP LOCKED`).
		Scan(&msgID, &channelID, &subject, &body, &priority, &attempt,
			&payloadRaw, &tenantID, &kind, &label, &secretRef, &cfgRaw)
	if err != nil {
		return false, nil // no due rows is the expected idle case
	}

	transport, ok := s.transports[kind]
	if !ok {
		_, _ = tx.Exec(ctx, `
			UPDATE notification_queue
			   SET state='quarantined', last_error=$2
			 WHERE id=$1`, msgID, "no transport registered for "+kind)
		return true, tx.Commit(ctx)
	}
	cfg := ChannelConfig{
		ID: channelID, TenantID: tenantID, Kind: kind, Label: label,
		SecretRef: secretRef,
	}
	_ = json.Unmarshal(cfgRaw, &cfg.Config)
	var payload map[string]any
	_ = json.Unmarshal(payloadRaw, &payload)

	resp, sendErr := transport.Send(ctx, cfg, Message{
		Subject: subject, Body: body, Priority: priority, Payload: payload,
	})
	if sendErr != nil {
		// Exponential backoff up to 1h: 1, 4, 16, 64, ... minutes.
		nextDelay := time.Duration(1<<min(uint(attempt), 6)) * time.Minute
		state := "failed"
		if attempt+1 >= 6 {
			state = "quarantined"
		}
		if _, err := tx.Exec(ctx, `
			UPDATE notification_queue
			   SET state=$2, attempt=attempt+1, last_error=$3,
			       next_attempt_at = now() + $4::interval
			 WHERE id=$1`,
			msgID, state, sendErr.Error(), nextDelay.String()); err != nil {
			return true, err
		}
		return true, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE notification_queue
		   SET state='delivered', attempt=attempt+1, delivered_at=now(),
		       last_error=NULL, payload = payload || jsonb_build_object('response', $2::text)
		 WHERE id=$1`, msgID, resp); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}

func min(a, b uint) uint {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// SMTP transport
// ============================================================================

type SMTPTransport struct {
	Host, Port, Username, Password, From string
	UseTLS                                bool
}

func (*SMTPTransport) Kind() string { return "email" }

func (t *SMTPTransport) Send(_ context.Context, cfg ChannelConfig, msg Message) (string, error) {
	to, _ := cfg.Config["to"].(string)
	if to == "" {
		return "", errors.New("smtp: channel config missing 'to' field")
	}
	from := t.From
	if v, ok := cfg.Config["from"].(string); ok && v != "" {
		from = v
	}
	hdr := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      msg.Subject,
		"Content-Type": "text/html; charset=UTF-8",
		"MIME-Version": "1.0",
	}
	var buf bytes.Buffer
	for k, v := range hdr {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	buf.WriteString(msg.Body)

	addr := t.Host + ":" + t.Port
	auth := smtp.PlainAuth("", t.Username, t.Password, t.Host)
	if t.UseTLS {
		// STARTTLS path is what most providers expect. The smtp.Dial
		// → c.StartTLS sequence is wrapped here for clarity.
		c, err := smtp.Dial(addr)
		if err != nil {
			return "", err
		}
		defer c.Close()
		if err := c.StartTLS(&tls.Config{ServerName: t.Host}); err != nil {
			return "", err
		}
		if err := c.Auth(auth); err != nil {
			return "", err
		}
		if err := c.Mail(from); err != nil {
			return "", err
		}
		if err := c.Rcpt(to); err != nil {
			return "", err
		}
		w, err := c.Data()
		if err != nil {
			return "", err
		}
		if _, err := w.Write(buf.Bytes()); err != nil {
			return "", err
		}
		if err := w.Close(); err != nil {
			return "", err
		}
		return "smtp 250 ok", c.Quit()
	}
	// Plain submission (lab / dev only).
	if err := smtp.SendMail(addr, auth, from, []string{to}, buf.Bytes()); err != nil {
		return "", err
	}
	return "smtp 250 ok", nil
}

// ============================================================================
// Twilio SMS transport
// ============================================================================

type TwilioTransport struct {
	AccountSID string
	AuthToken  string
	FromNumber string

	HTTP *http.Client
}

func (*TwilioTransport) Kind() string { return "sms" }

func (t *TwilioTransport) Send(ctx context.Context, cfg ChannelConfig, msg Message) (string, error) {
	to, _ := cfg.Config["to"].(string)
	if to == "" {
		return "", errors.New("sms: channel config missing 'to' (E.164 phone)")
	}
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + t.AccountSID + "/Messages.json"
	form := url.Values{}
	form.Set("To", to)
	form.Set("From", t.FromNumber)
	// SMS doesn't have a subject — concatenate as a short prefix.
	body := msg.Body
	if msg.Subject != "" {
		body = "[" + msg.Subject + "] " + body
	}
	if len(body) > 1500 {
		body = body[:1500] + "…"
	}
	form.Set("Body", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := t.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("twilio %d: %s", resp.StatusCode, body)
	}
	var doc struct {
		SID    string `json:"sid"`
		Status string `json:"status"`
	}
	body2, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(body2, &doc)
	return doc.SID + " " + doc.Status, nil
}

// ============================================================================
// PagerDuty Events v2 transport
// ============================================================================

type PagerDutyTransport struct {
	HTTP *http.Client
}

func (*PagerDutyTransport) Kind() string { return "pagerduty" }

func (t *PagerDutyTransport) Send(ctx context.Context, cfg ChannelConfig, msg Message) (string, error) {
	routingKey, _ := cfg.Config["routing_key"].(string)
	if routingKey == "" {
		return "", errors.New("pagerduty: channel config missing 'routing_key'")
	}
	sev := pdSeverity(msg.Priority)
	doc := map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("vaultscan-%s", msg.Payload["finding_id"]),
		"payload": map[string]any{
			"summary":   msg.Subject,
			"source":    "vaultscan",
			"severity":  sev,
			"component": "platform",
			"custom_details": map[string]any{
				"body":    truncate(msg.Body, 1024),
				"payload": msg.Payload,
			},
		},
	}
	body, _ := json.Marshal(doc)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://events.pagerduty.com/v2/enqueue", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := t.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("pagerduty %d: %s", resp.StatusCode, respBody)
	}
	var reply struct {
		DedupKey string `json:"dedup_key"`
		Status   string `json:"status"`
	}
	_ = json.Unmarshal(respBody, &reply)
	return reply.DedupKey + " " + reply.Status, nil
}

func pdSeverity(priority string) string {
	switch priority {
	case "urgent":
		return "critical"
	case "high":
		return "error"
	case "low":
		return "info"
	}
	return "warning"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
