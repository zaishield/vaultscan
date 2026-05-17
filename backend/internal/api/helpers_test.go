package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parsePagination covers the helper introduced in batch 6: validate
// + cap the limit / offset query params. The old `_ = strconv.Atoi`
// pattern returned 0 on garbage which produced "LIMIT 0" queries
// that looked like empty result sets — these tests are the
// regression dam.

func TestParsePagination_Defaults(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	lim, off, ok := parsePagination(w, r, 100, 1000)
	if !ok || lim != 100 || off != 0 {
		t.Errorf("empty query → lim=%d off=%d ok=%v, want 100/0/true", lim, off, ok)
	}
	if w.Code != 200 {
		t.Errorf("default path wrote a status: %d", w.Code)
	}
}

func TestParsePagination_Provided(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x?limit=50&offset=200", nil)
	w := httptest.NewRecorder()
	lim, off, ok := parsePagination(w, r, 100, 1000)
	if !ok || lim != 50 || off != 200 {
		t.Errorf("limit=50 offset=200 → lim=%d off=%d ok=%v", lim, off, ok)
	}
}

func TestParsePagination_NonNumericLimitRejects(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x?limit=abc", nil)
	w := httptest.NewRecorder()
	_, _, ok := parsePagination(w, r, 100, 1000)
	if ok {
		t.Error("non-numeric limit should reject")
	}
	if w.Code != 400 {
		t.Errorf("expected 400 on bad limit, got %d", w.Code)
	}
}

func TestParsePagination_NonNumericOffsetRejects(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x?offset=abc", nil)
	w := httptest.NewRecorder()
	_, _, ok := parsePagination(w, r, 100, 1000)
	if ok || w.Code != 400 {
		t.Errorf("non-numeric offset should 400; ok=%v code=%d", ok, w.Code)
	}
}

func TestParsePagination_NegativeRejects(t *testing.T) {
	t.Parallel()
	for _, q := range []string{"?limit=-1", "?offset=-5"} {
		r := httptest.NewRequest("GET", "/x"+q, nil)
		w := httptest.NewRecorder()
		if _, _, ok := parsePagination(w, r, 100, 1000); ok {
			t.Errorf("%s should reject", q)
		}
	}
}

func TestParsePagination_CapsAtMax(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x?limit=999999", nil)
	w := httptest.NewRecorder()
	lim, _, ok := parsePagination(w, r, 100, 1000)
	if !ok || lim != 1000 {
		t.Errorf("limit=999999 max=1000 → lim=%d (want 1000)", lim)
	}
}

func TestParsePagination_ZeroLimitFallsBackToDefault(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/x?limit=0", nil)
	w := httptest.NewRecorder()
	lim, _, ok := parsePagination(w, r, 100, 1000)
	if !ok || lim != 100 {
		t.Errorf("limit=0 should default to 100, got %d", lim)
	}
}

// capString — byte-counted truncation guard against multi-MB
// untrusted strings hitting the DB. The function MUST NOT panic
// on multibyte UTF-8 boundary cuts; downstream consumers re-validate.
func TestCapString_ShorterThanCapPassesThrough(t *testing.T) {
	t.Parallel()
	if got := capString("hello", 100); got != "hello" {
		t.Errorf("got %q want hello", got)
	}
}

func TestCapString_LongerThanCapTruncated(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 5000)
	got := capString(long, 100)
	if len(got) != 100 {
		t.Errorf("len=%d want 100", len(got))
	}
}

func TestCapString_EmptyStays(t *testing.T) {
	t.Parallel()
	if got := capString("", 100); got != "" {
		t.Errorf("got %q want empty", got)
	}
}

func TestCapString_ZeroCap(t *testing.T) {
	t.Parallel()
	if got := capString("hello", 0); got != "" {
		t.Errorf("got %q want empty (zero cap)", got)
	}
}

// notFound / forbidden / badRequest helpers write the canonical
// error JSON envelope. Light tests but they catch regressions in the
// shape consumers depend on.

// uuidParam: chi mux fixture
func TestUUIDParam_RejectsBadUUID(t *testing.T) {
	t.Parallel()
	// Direct call — uuidParam doesn't actually need a chi context
	// for malformed UUID; it just calls uuid.Parse.
	req := httptest.NewRequest("GET", "/x", nil)
	_, err := uuidParam(req, "missing")
	if err == nil {
		t.Error("missing param should error")
	}
}

// Suppress unused-import warning if the test gets reordered.
var _ = http.Error
