//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/db"
)

// TestReplicaLag_CurrentLSN exercises the freshness-token capture
// against a real Postgres. Without a replica configured (the test
// container is single-node), MeasureReplicaLagBytes returns an
// error because pg_last_wal_replay_lsn() only works on a replica.
// What we DO verify here:
//   * CurrentLSN against a single-node Postgres returns a non-
//     empty token. That's the primary's write position; even on a
//     single-node deploy it's the right cursor to stamp on writes
//     for downstream replica setup.
//   * ReaderFresh routes correctly when no replica is configured.
//   * ReadRoute.String() returns the documented labels.
func TestReplicaLag_CurrentLSNCapturesWritePosition(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	token1, err := db.CurrentLSN(ctx, h.pool)
	if err != nil {
		t.Fatalf("CurrentLSN #1: %v", err)
	}
	if token1.IsZero() {
		t.Fatal("CurrentLSN returned an empty token on a writable primary")
	}

	// Do a real write — this advances the WAL.
	if err := h.audit.Record(ctx, audit.Entry{
		PlatformID: platformID,
		Event:      "replica.lag.probe",
		ActorType:  "system",
		Payload:    map[string]any{"test": "lsn-advance"},
	}); err != nil {
		t.Fatalf("audit.Record: %v", err)
	}

	token2, err := db.CurrentLSN(ctx, h.pool)
	if err != nil {
		t.Fatalf("CurrentLSN #2: %v", err)
	}
	if token2.IsZero() {
		t.Fatal("token #2 empty")
	}
	if token1 == token2 {
		t.Logf("LSN unchanged across writes (token=%q) — single-node deploy or write batched", token1)
	} else {
		t.Logf("LSN advanced %q → %q after write — fence will work end-to-end", token1, token2)
	}
}

// TestReplicaLag_ReaderFreshFallsBackWithNoReplica — when no
// replica is configured, ReaderFresh MUST return the primary
// regardless of token.
func TestReplicaLag_ReaderFreshFallsBackWithNoReplica(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	token, err := db.CurrentLSN(ctx, h.pool)
	if err != nil {
		t.Fatal(err)
	}

	pool, route, err := db.ReaderFresh(ctx, h.pool, nil, token)
	if err != nil {
		t.Fatalf("ReaderFresh: %v", err)
	}
	if pool != h.pool {
		t.Error("ReaderFresh should return the primary when no replica is configured")
	}
	if route != db.ReadRoutePrimaryOnly {
		t.Errorf("route = %s, want primary_only", route)
	}

	// Same call with an empty token still returns primary in a
	// no-replica deployment.
	pool2, route2, _ := db.ReaderFresh(ctx, h.pool, nil, "")
	if pool2 != h.pool {
		t.Error("empty-token + no-replica should also return primary")
	}
	if route2 != db.ReadRoutePrimaryOnly {
		t.Errorf("empty-token route = %s, want primary_only", route2)
	}
}

// TestReplicaLag_RouteStrings — the operator-facing labels MUST be
// stable; Prometheus dashboards depend on them.
func TestReplicaLag_RouteStrings(t *testing.T) {
	cases := map[db.ReadRoute]string{
		db.ReadRoutePrimaryOnly:           "primary_only",
		db.ReadRouteReplicaUnfenced:       "replica_unfenced",
		db.ReadRouteReplicaCaughtUp:       "replica_caught_up",
		db.ReadRoutePrimaryDueToLag:       "primary_due_to_lag",
		db.ReadRouteFallbackOnReplicaError: "primary_replica_error",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", r, got, want)
		}
	}
}

// TestReplicaLag_TrackerSetGet round-trips the lag counter. Cheap
// but catches an atomic mis-wire.
func TestReplicaLag_TrackerSetGet(t *testing.T) {
	tr := &db.ReplicaLagTracker{}
	if tr.LagBytes() != 0 {
		t.Errorf("zero-value tracker should read 0, got %d", tr.LagBytes())
	}
	tr.SetLagBytes(12345)
	if got := tr.LagBytes(); got != 12345 {
		t.Errorf("after SetLagBytes(12345): got %d", got)
	}
}
