package audit

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestComputeRowHash_Determinism: same inputs → same hash, every time.
// Catches any non-determinism in the serialization (map iteration,
// time-zone drift, etc.) that would silently break chain verification
// on the next code change.
func TestComputeRowHash_Determinism(t *testing.T) {
	t.Parallel()
	occ := time.Date(2026, 1, 2, 3, 4, 5, 678901234, time.UTC)
	platID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	prev := []byte{0xab, 0xcd}

	for v := 1; v <= 2; v++ {
		a := computeRowHash(v, prev, occ, "ev", "user", nil, nil, nil,
			platID, nil, nil, nil, nil, `{"k":"v"}`)
		b := computeRowHash(v, prev, occ, "ev", "user", nil, nil, nil,
			platID, nil, nil, nil, nil, `{"k":"v"}`)
		if !bytes.Equal(a, b) {
			t.Errorf("v%d not deterministic: %x vs %x", v, a, b)
		}
	}
}

// TestComputeRowHash_V1V2Differ: v2 includes occurred_at; v1 doesn't.
// Same row through both algorithms must produce DIFFERENT hashes,
// otherwise the version-dispatch buys nothing.
func TestComputeRowHash_V1V2Differ(t *testing.T) {
	t.Parallel()
	occ := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	platID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	v1 := computeRowHash(1, nil, occ, "ev", "user", nil, nil, nil,
		platID, nil, nil, nil, nil, "{}")
	v2 := computeRowHash(2, nil, occ, "ev", "user", nil, nil, nil,
		platID, nil, nil, nil, nil, "{}")
	if bytes.Equal(v1, v2) {
		t.Fatal("v1 and v2 collide — version dispatch is a no-op")
	}
}

// TestComputeRowHash_V2OccurredAtSensitivity: two v2 rows that differ
// ONLY in occurred_at must produce different hashes. Closes the audit
// finding that motivated v2 in the first place.
func TestComputeRowHash_V2OccurredAtSensitivity(t *testing.T) {
	t.Parallel()
	platID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC) // +1 sec
	h1 := computeRowHash(2, nil, t1, "ev", "user", nil, nil, nil, platID, nil, nil, nil, nil, "{}")
	h2 := computeRowHash(2, nil, t2, "ev", "user", nil, nil, nil, platID, nil, nil, nil, nil, "{}")
	if bytes.Equal(h1, h2) {
		t.Fatal("v2 hash not sensitive to occurred_at")
	}
}

// TestComputeRowHash_PrevBinding: hash depends on `prev`. A row whose
// prev was tampered with must not silently re-validate.
func TestComputeRowHash_PrevBinding(t *testing.T) {
	t.Parallel()
	platID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	occ := time.Now().UTC()
	prevA := []byte{0x01}
	prevB := []byte{0x02}
	hA := computeRowHash(2, prevA, occ, "ev", "user", nil, nil, nil, platID, nil, nil, nil, nil, "{}")
	hB := computeRowHash(2, prevB, occ, "ev", "user", nil, nil, nil, platID, nil, nil, nil, nil, "{}")
	if bytes.Equal(hA, hB) {
		t.Fatal("hash not sensitive to chain_prev")
	}
}

// TestComputeRowHash_NilEmptyDistinction: nil *string vs &"" must hash
// the same (canonicalString treats both as empty), and a non-empty
// string must hash differently. Without this, a future refactor that
// changes how empty strings are represented could silently break
// historical chain verification.
func TestComputeRowHash_NilEmptyDistinction(t *testing.T) {
	t.Parallel()
	empty := ""
	val := "x"
	platID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	occ := time.Now().UTC()
	hNil := computeRowHash(2, nil, occ, "ev", "user", nil, nil, &empty,
		platID, nil, nil, nil, nil, "{}")
	hEmpty := computeRowHash(2, nil, occ, "ev", "user", nil, nil, &empty,
		platID, nil, nil, nil, nil, "{}")
	hVal := computeRowHash(2, nil, occ, "ev", "user", nil, nil, &val,
		platID, nil, nil, nil, nil, "{}")
	if !bytes.Equal(hNil, hEmpty) {
		t.Fatal("nil and empty-string ua should hash the same")
	}
	if bytes.Equal(hNil, hVal) {
		t.Fatal("nil ua collides with non-empty ua hash")
	}
}
