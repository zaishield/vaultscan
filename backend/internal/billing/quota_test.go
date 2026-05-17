package billing

import (
	"errors"
	"testing"
	"time"
)

// IsQuotaExceeded — type-check helper used by API translators.
func TestIsQuotaExceeded(t *testing.T) {
	t.Parallel()
	qe := &ErrQuotaExceeded{Kind: KindAsset, Plan: "starter", Current: 100, Limit: 100}
	if !IsQuotaExceeded(qe) {
		t.Error("expected typed ErrQuotaExceeded to be detected")
	}
	if !IsQuotaExceeded(wrappedErr{qe}) {
		t.Error("expected wrapped ErrQuotaExceeded to be detected via errors.As")
	}
	if IsQuotaExceeded(errors.New("other")) {
		t.Error("plain error should not match")
	}
	if IsQuotaExceeded(nil) {
		t.Error("nil should not match")
	}
}

type wrappedErr struct{ err error }

func (w wrappedErr) Error() string { return "wrapped: " + w.err.Error() }
func (w wrappedErr) Unwrap() error { return w.err }

// currentCycleStart — billing-period anchor math. Tests independent
// of DB so the cycle boundaries are pinned for invoice consistency.
func TestCurrentCycleStart_Monthly(t *testing.T) {
	t.Parallel()
	// Plan signed on the 15th of January.
	anchor := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		now  time.Time
		want time.Time
	}{
		// Mid first cycle: cycle started on Jan 15.
		{time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
		// Just inside second cycle (Feb 16).
		{time.Date(2026, 2, 16, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)},
		// Several months in.
		{time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		got := currentCycleStart(anchor, "monthly", c.now)
		if !got.Equal(c.want) {
			t.Errorf("currentCycleStart(monthly, now=%s) = %s, want %s",
				c.now.Format("2006-01-02"), got.Format("2006-01-02"), c.want.Format("2006-01-02"))
		}
	}
}

func TestCurrentCycleStart_Quarterly(t *testing.T) {
	t.Parallel()
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// April 5 is in the Q2 cycle that started April 1.
	got := currentCycleStart(anchor, "quarterly", time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC))
	want := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("quarterly: got %s want %s",
			got.Format("2006-01-02"), want.Format("2006-01-02"))
	}
}

func TestCurrentCycleStart_Annually(t *testing.T) {
	t.Parallel()
	anchor := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	// 2026 sits in the cycle that started 2026-03-15.
	got := currentCycleStart(anchor, "annually", time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC))
	want := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("annually: got %s want %s",
			got.Format("2006-01-02"), want.Format("2006-01-02"))
	}
}

// Anchor in the future → return the anchor unchanged (no cycle has
// started yet).
func TestCurrentCycleStart_FutureAnchorReturnsAnchor(t *testing.T) {
	t.Parallel()
	anchor := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	got := currentCycleStart(anchor, "monthly", time.Now().UTC())
	if !got.Equal(anchor) {
		t.Errorf("future anchor: got %s want %s", got, anchor)
	}
}

// planLabel — prefers Name when set, falls back to PlanCode.
func TestPlanLabel(t *testing.T) {
	t.Parallel()
	if planLabel(&Plan{PlanCode: "starter"}) != "starter" {
		t.Error("empty name should fall back to PlanCode")
	}
	if planLabel(&Plan{PlanCode: "starter", Name: "Starter Tier"}) != "Starter Tier" {
		t.Error("Name should win when set")
	}
}

// ErrQuotaExceeded.Error message is operator-visible; pin its shape.
func TestErrQuotaExceededMessage(t *testing.T) {
	t.Parallel()
	e := &ErrQuotaExceeded{Kind: KindScan, Plan: "growth", Current: 1001, Limit: 1000}
	want := `billing: scan quota exceeded on plan "growth" (using 1001 of 1000)`
	if e.Error() != want {
		t.Errorf("got %q want %q", e.Error(), want)
	}
}
