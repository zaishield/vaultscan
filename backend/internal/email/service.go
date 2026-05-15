// Package email manages branded per-partner email templates and dispatch.
// Production sits on a real SMTP relay (or SES / Postmark); the dev mode
// records sent messages in-memory so tests can assert on them. Blueprint
// §8.4 (white-label email) + §31.2 (notification channel).
package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool      *pgxpool.Pool
	transport Transport
}

func New(pool *pgxpool.Pool, t Transport) *Service {
	if t == nil {
		t = &MemoryTransport{}
	}
	return &Service{pool: pool, transport: t}
}

// Transport sends a rendered message. Production wires SMTP / SES; tests
// use MemoryTransport.
type Transport interface {
	Send(ctx context.Context, msg Message) error
}

type Message struct {
	From     string
	To       []string
	Subject  string
	BodyHTML string
	BodyText string
	Headers  map[string]string
}

// MemoryTransport collects messages in-memory for testing.
type MemoryTransport struct {
	mu   sync.Mutex
	sent []Message
}

func (m *MemoryTransport) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}
func (m *MemoryTransport) Sent() []Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Message, len(m.sent))
	copy(cp, m.sent)
	return cp
}

// ----- Template CRUD --------------------------------------------------------

type Template struct {
	ID         uuid.UUID `json:"id"`
	PartnerID  uuid.UUID `json:"partner_id"`
	Code       string    `json:"code"`
	Subject    string    `json:"subject"`
	BodyHTML   string    `json:"body_html"`
	BodyText   string    `json:"body_text"`
}

func (s *Service) Upsert(ctx context.Context, partnerID uuid.UUID, t Template) error {
	if t.Code == "" || t.Subject == "" {
		return errors.New("email: code + subject required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO partner_email_templates(partner_id, code, subject, body_html, body_text)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (partner_id, code) DO UPDATE SET
		    subject=EXCLUDED.subject, body_html=EXCLUDED.body_html,
		    body_text=EXCLUDED.body_text, updated_at=now()`,
		partnerID, t.Code, t.Subject, t.BodyHTML, t.BodyText)
	return err
}

func (s *Service) Get(ctx context.Context, partnerID uuid.UUID, code string) (*Template, error) {
	t := &Template{PartnerID: partnerID, Code: code}
	err := s.pool.QueryRow(ctx, `
		SELECT id, subject, COALESCE(body_html,''), COALESCE(body_text,'')
		  FROM partner_email_templates WHERE partner_id=$1 AND code=$2`,
		partnerID, code).Scan(&t.ID, &t.Subject, &t.BodyHTML, &t.BodyText)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Service) List(ctx context.Context, partnerID uuid.UUID) ([]Template, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, partner_id, code, subject, COALESCE(body_html,''), COALESCE(body_text,'')
		  FROM partner_email_templates WHERE partner_id=$1 ORDER BY code`, partnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.ID, &t.PartnerID, &t.Code, &t.Subject, &t.BodyHTML, &t.BodyText); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ----- Rendering + dispatch -------------------------------------------------

// SendInput renders a partner-scoped template with the given context and
// sends via the configured transport.
type SendInput struct {
	PartnerID uuid.UUID
	Code      string
	To        []string
	Vars      map[string]any
}

func (s *Service) Send(ctx context.Context, in SendInput) (*Message, error) {
	if len(in.To) == 0 {
		return nil, errors.New("email: at least one recipient required")
	}
	tmpl, err := s.Get(ctx, in.PartnerID, in.Code)
	if err != nil {
		return nil, fmt.Errorf("email: load template %s: %w", in.Code, err)
	}
	subject, err := renderString("subject", tmpl.Subject, in.Vars)
	if err != nil {
		return nil, err
	}
	bodyHTML, err := renderString("html", tmpl.BodyHTML, in.Vars)
	if err != nil {
		return nil, err
	}
	bodyText, err := renderString("text", tmpl.BodyText, in.Vars)
	if err != nil {
		return nil, err
	}

	// Resolve the partner's sender identity.
	var sender, senderName string
	_ = s.pool.QueryRow(ctx, `
		SELECT COALESCE(sender_email,''), COALESCE(sender_name,'')
		  FROM partner_branding WHERE partner_id=$1`, in.PartnerID).
		Scan(&sender, &senderName)
	from := sender
	if senderName != "" && sender != "" {
		from = fmt.Sprintf("%s <%s>", senderName, sender)
	}

	msg := Message{
		From: from, To: in.To, Subject: subject,
		BodyHTML: bodyHTML, BodyText: bodyText,
		Headers: map[string]string{"X-Vaultscan-Partner": in.PartnerID.String()},
	}
	if err := s.transport.Send(ctx, msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// SendTest dispatches a small canned payload to verify the template +
// sender domain + transport are wired correctly.
func (s *Service) SendTest(ctx context.Context, partnerID uuid.UUID, code, to string) (*Message, error) {
	return s.Send(ctx, SendInput{
		PartnerID: partnerID, Code: code,
		To: []string{to},
		Vars: map[string]any{
			"recipient_name":    "Operator",
			"product_name":      "VAULTSCAN",
			"finding_severity":  "high",
			"finding_title":     "Test alert",
			"engagement_code":   "ENG-TEST-000",
		},
	})
}

func renderString(name, src string, vars map[string]any) (string, error) {
	if src == "" {
		return "", nil
	}
	t, err := template.New(name).Parse(src)
	if err != nil {
		return "", fmt.Errorf("email: parse %s: %w", name, err)
	}
	var buf strings.Builder
	if err := t.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("email: render %s: %w", name, err)
	}
	return buf.String(), nil
}
