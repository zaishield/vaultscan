// Package eventbus implements the in-process event bus described in
// Blueprint §22. The persistence half stores every event in bus_events;
// in production the same Publish call would also push to NATS/Kafka so
// external consumers (notifications, SIEM, integrations) receive it.
package eventbus

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// busLogger handles subscriber-panic diagnostics. Kept package-local
// so callers don't have to inject a logger into Publish — the bus
// already lives behind a global registry pattern.
var busLogger = zerolog.New(os.Stderr).With().Timestamp().Str("component", "eventbus").Logger()

// Canonical event type list from Blueprint §22.1.
const (
	TenantCreated           = "TenantCreated"
	PartnerCreated          = "PartnerCreated"
	EngagementCreated       = "EngagementCreated"
	AuthorizationUploaded   = "AuthorizationUploaded"
	ScopeApproved           = "ScopeApproved"
	ScanJobCreated          = "ScanJobCreated"
	ScanJobApproved         = "ScanJobApproved"
	ExternalScanStarted     = "ExternalScanStarted"
	InternalScanDispatched  = "InternalScanDispatched"
	AgentHeartbeatReceived  = "AgentHeartbeatReceived"
	AgentWentOffline        = "AgentWentOffline"
	ScannerOutputReceived   = "ScannerOutputReceived"
	FindingNormalized       = "FindingNormalized"
	FindingDeduplicated     = "FindingDeduplicated"
	FindingAssigned         = "FindingAssigned"
	RetestRequested         = "RetestRequested"
	RetestPassed            = "RetestPassed"
	RetestFailed            = "RetestFailed"
	ReportGenerated         = "ReportGenerated"
	EvidenceDownloaded      = "EvidenceDownloaded"
	EmergencyStopTriggered  = "EmergencyStopTriggered"
)

// AllEventTypes returns every event type the bus knows about.
func AllEventTypes() []string {
	return []string{
		TenantCreated, PartnerCreated, EngagementCreated, AuthorizationUploaded,
		ScopeApproved, ScanJobCreated, ScanJobApproved, ExternalScanStarted,
		InternalScanDispatched, AgentHeartbeatReceived, AgentWentOffline,
		ScannerOutputReceived, FindingNormalized, FindingDeduplicated,
		FindingAssigned, RetestRequested, RetestPassed, RetestFailed,
		ReportGenerated, EvidenceDownloaded, EmergencyStopTriggered,
	}
}

type Event struct {
	ID         uuid.UUID
	Type       string
	TenantID   *uuid.UUID
	PartnerID  *uuid.UUID
	ActorID    *uuid.UUID
	Payload    map[string]any
}

type Handler func(ctx context.Context, ev Event)

type Bus struct {
	pool       *pgxpool.Pool
	mu         sync.RWMutex
	handlers   map[string][]Handler

	// External sinks (NATS / Kafka / etc.) — see external.go.
	extMu sync.RWMutex
	ext   []ExternalSink
	// extWg tracks in-flight external Forward goroutines so DrainExternal
	// can block on shutdown until they complete (or the drain deadline
	// trips).
	extWg sync.WaitGroup
}

func New(pool *pgxpool.Pool) *Bus {
	return &Bus{pool: pool, handlers: map[string][]Handler{}}
}

func (b *Bus) Subscribe(eventType string, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], h)
}

// Publish stores the event in bus_events and fans out to in-process consumers.
func (b *Bus) Publish(ctx context.Context, ev Event) error {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return err
	}
	if _, err := b.pool.Exec(ctx, `
		INSERT INTO bus_events(id, event_type, tenant_id, partner_id, actor_id, payload)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		ev.ID, ev.Type, ev.TenantID, ev.PartnerID, ev.ActorID, payload); err != nil {
		return err
	}
	b.mu.RLock()
	hs := b.handlers[ev.Type]
	wild := b.handlers["*"]
	b.mu.RUnlock()
	for _, h := range hs {
		go safeHandle(h, ctx, ev)
	}
	for _, h := range wild {
		go safeHandle(h, ctx, ev)
	}
	// External sinks fire after in-process fan-out. Failures here
	// don't affect bus_events durability — Publish has already
	// committed the row.
	b.publishExternal(ev)
	return nil
}

// safeHandle wraps a subscriber call in a panic recovery so one
// buggy adapter can't take down the process. The recovered panic
// is logged via the package logger; the message stays in flight
// (we don't re-deliver to that single subscriber, but every other
// subscriber continues to receive the event).
func safeHandle(h Handler, ctx context.Context, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			busLogger.Error().
				Interface("panic", r).
				Str("event_type", ev.Type).
				Str("event_id", ev.ID.String()).
				Msg("eventbus: subscriber panicked; recovered")
		}
	}()
	h(ctx, ev)
}
