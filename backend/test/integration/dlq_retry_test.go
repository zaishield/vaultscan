//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/integrations"
)

// TestDLQRetry_GivesUpAfterMaxRetries proves the operator-free
// retry sweeper terminates instead of looping forever. Once
// retry_count exceeds the per-row cap, give_up_at is set and the
// sweeper ignores it from then on. The integrations.deliver path
// runs its own 4-attempt exponential backoff (1s/2s/4s/8s) on
// every Replay call, so we DON'T drive give-up via real retries —
// that would take minutes. We seed the DB into the high-retry-count
// state, then call the sweeper once to assert give-up triggers.
func TestDLQRetry_GivesUpAfterMaxRetries(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// Mark every pre-existing pending DLQ row as resolved so the
	// sweeper's global SELECT only sees rows this test enqueues.
	// Without isolation, a sibling test's deliver-path could have
	// left a fresh DLQ row that our sweep would pick up.
	if _, err := h.pool.Exec(ctx,
		`UPDATE integration_dead_letters SET resolved_at = now(), resolution = 'dropped'
		  WHERE resolved_at IS NULL AND give_up_at IS NULL`); err != nil {
		t.Fatalf("dlq isolation: %v", err)
	}
	tenantID, _ := h.makeTenant(t, "dlq-giveup-"+uuid.NewString()[:6])

	// Unreachable URL — Replay() will always fail. We only retry once
	// (the sweeper increments retry_count before calling Replay).
	id := createIntegration(t, h, tenantID, "webhook",
		"dlq-giveup-"+uuid.NewString()[:6],
		map[string]any{"url": "http://127.0.0.1:1"})

	svc := integrations.New(h.pool, h.bus, h.audit)
	ev := eventbus.Event{
		ID: uuid.New(), Type: "finding.created",
		TenantID: &tenantID, PartnerID: &directID,
		Payload: map[string]any{"severity": "high"},
	}
	dlqID, err := svc.EnqueueDeadLetter(ctx, id, ev, 5, "initial failure", 0)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Seed the row at retry_count = maxRetries-1. The next sweep
	// increments to maxRetries → give_up_at must be set.
	maxRetries := 3
	if _, err := h.pool.Exec(ctx, `
		UPDATE integration_dead_letters
		   SET retry_count = $2, last_retry_at = NULL
		 WHERE id = $1`, dlqID, maxRetries-1); err != nil {
		t.Fatalf("seed retry_count: %v", err)
	}

	retriedN, succeededN, gaveUpN, err := svc.RetryDeadLetters(ctx, 10, maxRetries)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	t.Logf("sweep1: retried=%d succeeded=%d gaveUp=%d", retriedN, succeededN, gaveUpN)

	var giveUp *time.Time
	var retryCount int
	var lastRetry *time.Time
	var resolved *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT give_up_at, retry_count, last_retry_at, resolved_at
		   FROM integration_dead_letters WHERE id = $1`,
		dlqID).Scan(&giveUp, &retryCount, &lastRetry, &resolved); err != nil {
		t.Fatalf("read row: %v", err)
	}
	t.Logf("row state: retry_count=%d last_retry_at=%v resolved_at=%v give_up_at=%v",
		retryCount, lastRetry, resolved, giveUp)
	if giveUp == nil {
		t.Errorf("expected give_up_at to be set after retry_count reached %d (got retry_count=%d)",
			maxRetries, retryCount)
	}

	// Second sweep: the given-up row MUST NOT be touched. Other
	// rows (e.g. fresh DLQ entries the deliver path enqueued when
	// the Replay re-failed) are out of scope here — they'll have
	// their own retry_count=0 trajectory.
	beforeRetryCount := retryCount
	if _, _, _, err := svc.RetryDeadLetters(ctx, 10, maxRetries); err != nil {
		t.Fatalf("post-give-up sweep: %v", err)
	}
	var afterRetryCount int
	var afterGiveUp *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT retry_count, give_up_at FROM integration_dead_letters WHERE id = $1`,
		dlqID).Scan(&afterRetryCount, &afterGiveUp); err != nil {
		t.Fatalf("re-read row: %v", err)
	}
	if afterRetryCount != beforeRetryCount {
		t.Errorf("given-up row's retry_count advanced from %d to %d on a sweep that should have skipped it",
			beforeRetryCount, afterRetryCount)
	}
	if afterGiveUp == nil {
		t.Error("give_up_at unexpectedly cleared")
	}
}

// TestDLQRetry_BackoffPreventsRapidRefire — a row retried at T must
// not be retried again until T + (2^retry_count) minutes. Closes the
// thundering-herd hole where the previous helper would re-attempt
// every 5 minutes regardless of how many retries had just fired.
func TestDLQRetry_BackoffPreventsRapidRefire(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx,
		`UPDATE integration_dead_letters SET resolved_at = now(), resolution = 'dropped'
		  WHERE resolved_at IS NULL AND give_up_at IS NULL`); err != nil {
		t.Fatalf("dlq isolation: %v", err)
	}
	tenantID, _ := h.makeTenant(t, "dlq-backoff-"+uuid.NewString()[:6])
	id := createIntegration(t, h, tenantID, "webhook",
		"dlq-backoff-"+uuid.NewString()[:6],
		map[string]any{"url": "http://127.0.0.1:1"})

	svc := integrations.New(h.pool, h.bus, h.audit)
	ev := eventbus.Event{
		ID: uuid.New(), Type: "finding.created",
		TenantID: &tenantID, PartnerID: &directID,
	}
	dlqID, err := svc.EnqueueDeadLetter(ctx, id, ev, 1, "first failure", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Seed retry_count=2 so the backoff predicate compares
	// last_retry_at to (now - 4 minutes). Stamp last_retry_at to
	// now() — guaranteed inside the window, so the sweeper MUST
	// skip the row.
	if _, err := h.pool.Exec(ctx, `
		UPDATE integration_dead_letters
		   SET retry_count = 2, last_retry_at = now()
		 WHERE id = $1`, dlqID); err != nil {
		t.Fatal(err)
	}

	// Diagnostic: list every pending row so we know whether the
	// retry hit OUR row or some other pre-existing one.
	dbgRows, _ := h.pool.Query(ctx, `
		SELECT id, retry_count, last_retry_at, give_up_at, resolved_at
		  FROM integration_dead_letters
		 WHERE integration_id = $1`, id)
	for dbgRows.Next() {
		var did uuid.UUID
		var rc int
		var lr, gu, ra *time.Time
		_ = dbgRows.Scan(&did, &rc, &lr, &gu, &ra)
		t.Logf("DLQ row: id=%s retry_count=%d last_retry=%v give_up=%v resolved=%v",
			did, rc, lr, gu, ra)
	}
	dbgRows.Close()

	// Diagnostic: show exactly what the sweep's SELECT would return.
	probeRows, _ := h.pool.Query(ctx, `
		SELECT id, retry_count, last_retry_at,
		       now() - (POWER(2, retry_count)::text || ' minutes')::interval AS threshold,
		       (last_retry_at IS NULL OR last_retry_at < now() - (POWER(2, retry_count)::text || ' minutes')::interval) AS due
		  FROM integration_dead_letters
		 WHERE resolved_at IS NULL AND give_up_at IS NULL`)
	for probeRows.Next() {
		var pid uuid.UUID
		var rc int
		var lr, thr *time.Time
		var due bool
		_ = probeRows.Scan(&pid, &rc, &lr, &thr, &due)
		t.Logf("PROBE: id=%s rc=%d last_retry=%v threshold=%v due=%v", pid, rc, lr, thr, due)
	}
	probeRows.Close()

	retried, _, _, err := svc.RetryDeadLetters(ctx, 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	if retried != 0 {
		t.Errorf("backoff broken: row within its window was retried (count=%d)", retried)
	}

	// Confirm advancing last_retry_at backward (simulate "enough
	// time has passed") makes the row due again.
	if _, err := h.pool.Exec(ctx,
		`UPDATE integration_dead_letters SET last_retry_at = now() - interval '10 minutes' WHERE id = $1`,
		dlqID); err != nil {
		t.Fatal(err)
	}
	retried, _, _, err = svc.RetryDeadLetters(ctx, 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	if retried != 1 {
		t.Errorf("expected 1 retry after backoff window elapsed; got %d", retried)
	}
}
