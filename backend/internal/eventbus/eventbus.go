// Package eventbus implements the in-process event bus described in
// Blueprint §22. The persistence half stores every event in bus_events;
// in production the same Publish call would also push to NATS/Kafka so
// external consumers (notifications, SIEM, integrations) receive it.
package eventbus

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

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
	// Billing-quota events (Blueprint §8.7). Block is emitted on a
	// hard rejection (overage_policy=block); Warning is emitted on
	// soft-cap pass-through (overage_policy=warn); PlanChanged
	// fires when AssignPlan succeeds.
	PartnerQuotaBlocked  = "PartnerQuotaBlocked"
	PartnerQuotaWarning  = "PartnerQuotaWarning"
	PartnerPlanChanged   = "PartnerPlanChanged"

	// External + internal plane events (migration 0061). Listed
	// here so integrations + the analytics indexer can subscribe.
	TenantSSOConfigured        = "TenantSSOConfigured"
	TenantSCIMTokenCreated     = "TenantSCIMTokenCreated"
	TenantSCIMTokenRevoked     = "TenantSCIMTokenRevoked"
	TenantQuarantined          = "TenantQuarantined"
	TenantQuarantineCancelled  = "TenantQuarantineCancelled"
	TenantMigratedToPartner    = "TenantMigratedToPartner"
	PartnerPlanChangeRequested = "PartnerPlanChangeRequested"
	PartnerPlanChangeDecided   = "PartnerPlanChangeDecided"
	SupportImpersonationStarted = "SupportImpersonationStarted"
	SupportImpersonationEnded   = "SupportImpersonationEnded"
	BillingUsageAdjusted        = "BillingUsageAdjusted"
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
		PartnerQuotaBlocked, PartnerQuotaWarning, PartnerPlanChanged,
		TenantSSOConfigured, TenantSCIMTokenCreated, TenantSCIMTokenRevoked,
		TenantQuarantined, TenantQuarantineCancelled, TenantMigratedToPartner,
		PartnerPlanChangeRequested, PartnerPlanChangeDecided,
		SupportImpersonationStarted, SupportImpersonationEnded,
		BillingUsageAdjusted,
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
	// shutdownCtx is cancelled when DrainExternal starts; in-flight
	// publishExternal goroutines derive their per-call ctx from this
	// so SIGTERM propagates into the Forward call instead of waiting
	// for the 5s per-call deadline to elapse.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// Postgres NOTIFY/LISTEN bridge — see pg_notify.go.
	notifyMu      sync.RWMutex
	notifyEnabled bool
}

func New(pool *pgxpool.Pool) *Bus {
	ctx, cancel := context.WithCancel(context.Background())
	return &Bus{
		pool: pool, handlers: map[string][]Handler{},
		shutdownCtx: ctx, shutdownCancel: cancel,
	}
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
	// Postgres NOTIFY for cross-process delivery (no-op until
	// EnableNotify is called by the producer process).
	b.emitNotify(ctx, ev)
	return nil
}

// safeHandle wraps a subscriber call in:
//   - a panic recovery so one buggy adapter can't take down the
//     process. Recovered panic is logged with event metadata; we
//     don't re-deliver to that subscriber, but every other handler
//     continues to receive the event.
//   - a per-handler timeout (handlerTimeout, default 30s) so a
//     slow / stuck subscriber can't accumulate goroutines indefinitely.
//     The handler's ctx is derived from the publisher's ctx with the
//     timeout layered on top — if the publisher ctx is already
//     short, that wins.
func safeHandle(h Handler, ctx context.Context, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			// Capture which handler function panicked. Without
			// this, an event with many subscribers gives no signal
			// pointing at the culprit — operator has to grep
			// through the recovered panic value for clues. The
			// FuncForPC walk is best-effort: it returns "" if
			// the function was a closure or otherwise opaque, in
			// which case we still log the event metadata.
			handlerName := ""
			if pc := reflect.ValueOf(h).Pointer(); pc != 0 {
				if fn := runtime.FuncForPC(pc); fn != nil {
					handlerName = fn.Name()
				}
			}
			busLogger.Error().
				Interface("panic", r).
				Str("event_type", ev.Type).
				Str("event_id", ev.ID.String()).
				Str("handler", handlerName).
				Bytes("stack", debug.Stack()).
				Msg("eventbus: subscriber panicked; recovered")
		}
	}()
	hctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()
	h(hctx, ev)
}

// handlerTimeout caps how long a single subscriber may run. 30s is
// generous against the historical p95 for in-process handlers
// (microseconds for log fan-out, ~tens of milliseconds for external
// integrations); a handler exceeding this is almost certainly stuck
// and we'd rather lose its result than leak a goroutine forever.
var handlerTimeout = 30 * time.Second
