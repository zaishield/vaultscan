// pg_notify_bridge — uses Postgres NOTIFY/LISTEN to fan published events
// across processes without needing NATS/Kafka in the dependency tree.
//
// Architecture:
//
//   ┌─────────────┐    NOTIFY                ┌─────────────┐
//   │ producer    │ ─────────────► postgres ─┤ subscriber  │
//   │ api / worker│   LISTEN ─────►          │ analytics   │
//   └─────────────┘                          └─────────────┘
//
// Wire format (one channel: "vaultscan_events"):
//   {"id":"<uuid>","type":"FindingNormalized",
//    "tenant_id":"...","partner_id":"...","actor_id":"...",
//    "payload":{...}}
//
// Failure modes:
//   * Payload too large for NOTIFY (8000 bytes) — fall back to bus_events
//     poll with WHERE id > last_seen.
//   * Producer crashes mid-NOTIFY — event still persisted in bus_events,
//     consumer's catch-up poll picks it up.
//   * Consumer crashes — bus_events.last_seen_at marker on the consumer's
//     state row lets it resume from where it stopped.
//
// This is a step short of full NATS/Kafka: no consumer groups, no
// at-least-once, no replay-from-offset. But it solves the immediate
// gap — analytics-worker + searchindex + integrations now see events
// emitted by other processes in <100ms, without operating a new
// piece of infrastructure.

package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NotifyChannel is the Postgres LISTEN channel name. All processes
// publishing or consuming events use the same name.
const NotifyChannel = "vaultscan_events"

// notifyPayload is the JSON shape sent over NOTIFY. Keep it compact —
// the 8000-byte NOTIFY limit is small, so payloads that don't fit
// signal the consumer to fall back to a SELECT on bus_events.id.
type notifyPayload struct {
	ID         uuid.UUID       `json:"id"`
	Type       string          `json:"type"`
	TenantID   *uuid.UUID      `json:"tenant_id,omitempty"`
	PartnerID  *uuid.UUID      `json:"partner_id,omitempty"`
	ActorID    *uuid.UUID      `json:"actor_id,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// EnableNotify wires a NOTIFY emission into every successful Publish.
// Call once at boot from any process that needs to broadcast events.
// Idempotent: calling twice replaces the prior wiring.
func (b *Bus) EnableNotify() {
	b.notifyMu.Lock()
	defer b.notifyMu.Unlock()
	b.notifyEnabled = true
}

// emitNotify is called from Publish after bus_events insert succeeds.
// Best-effort: an emission failure is logged but does not fail Publish
// (bus_events is the durable source; NOTIFY is just the fast path).
func (b *Bus) emitNotify(ctx context.Context, ev Event) {
	b.notifyMu.RLock()
	enabled := b.notifyEnabled
	b.notifyMu.RUnlock()
	if !enabled {
		return
	}
	rawPayload, _ := json.Marshal(ev.Payload)
	body, err := json.Marshal(notifyPayload{
		ID: ev.ID, Type: ev.Type,
		TenantID: ev.TenantID, PartnerID: ev.PartnerID, ActorID: ev.ActorID,
		Payload: rawPayload,
	})
	if err != nil {
		busLogger.Warn().Err(err).Msg("eventbus: marshal notify payload")
		return
	}
	// NOTIFY can't carry more than 8000 bytes. For oversized events
	// we still NOTIFY a "marker" payload so consumers know to read
	// the full event from bus_events.
	if len(body) > 7500 {
		body, _ = json.Marshal(notifyPayload{ID: ev.ID, Type: ev.Type})
	}
	// pq_notify accepts the channel name and an arbitrary string.
	// We escape single quotes with $tag$ ... $tag$ dollar-quoting.
	q := fmt.Sprintf(`NOTIFY %s, %s`,
		NotifyChannel, dollarQuote(string(body)))
	if _, err := b.pool.Exec(ctx, q); err != nil {
		busLogger.Warn().Err(err).Msg("eventbus: NOTIFY failed (continuing)")
	}
}

func dollarQuote(s string) string {
	// pick a tag that doesn't appear in s
	tag := "ev"
	for strings.Contains(s, "$"+tag+"$") {
		tag += "x"
	}
	return "$" + tag + "$" + s + "$" + tag + "$"
}

// StartListener spawns a goroutine that LISTENs on NotifyChannel and
// invokes the bus's in-process handlers for each received event. Use
// from any consumer process (analytics-worker, searchindex worker,
// etc.) that wants cross-process delivery. Blocks until ctx is
// cancelled or the LISTEN conn dies; on conn loss it reconnects with
// exponential backoff.
//
// Events arriving here run through the same Subscribe()-registered
// handlers as in-process events.
func (b *Bus) StartListener(ctx context.Context) {
	go b.runListener(ctx)
}

func (b *Bus) runListener(ctx context.Context) {
	backoff := time.Second
	for {
		if err := b.listenOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			busLogger.Warn().Err(err).Dur("backoff", backoff).
				Msg("eventbus: listener error; reconnecting")
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (b *Bus) listenOnce(ctx context.Context) error {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+NotifyChannel); err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var p notifyPayload
		if err := json.Unmarshal([]byte(n.Payload), &p); err != nil {
			busLogger.Warn().Err(err).Msg("eventbus: bad NOTIFY payload")
			continue
		}
		ev := Event{
			ID: p.ID, Type: p.Type,
			TenantID: p.TenantID, PartnerID: p.PartnerID, ActorID: p.ActorID,
		}
		if len(p.Payload) > 0 {
			_ = json.Unmarshal(p.Payload, &ev.Payload)
		} else if len(n.Payload) <= 100 {
			// Payload was truncated → fetch from bus_events
			if pl, err := b.fetchEventPayload(ctx, p.ID); err == nil {
				ev.Payload = pl
			}
		}
		// Run through the normal subscriber set.
		b.dispatchLocal(ctx, ev)
	}
}

func (b *Bus) fetchEventPayload(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	var raw []byte
	if err := b.pool.QueryRow(ctx,
		`SELECT payload FROM bus_events WHERE id=$1`, id).Scan(&raw); err != nil {
		return nil, err
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

// dispatchLocal runs an event through the in-process handlers without
// re-NOTIFYing — used by the listener to avoid an emit loop.
func (b *Bus) dispatchLocal(ctx context.Context, ev Event) {
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
}

var _ = (*pgxpool.Pool)(nil) // keep import live
