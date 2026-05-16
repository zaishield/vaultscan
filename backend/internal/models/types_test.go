package models

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// models is mostly type definitions, but it exports two canonical
// slices that the rest of the platform depends on for validation:
// FindingStatuses and SeverityLevels. The shape of these slices is
// part of the API surface — if anyone reorders or trims them, finding
// validation and severity ranking break system-wide.

func TestFindingStatuses_ExactSet(t *testing.T) {
	t.Parallel()
	want := []string{
		"open", "triaged", "assigned", "in_progress", "risk_accepted",
		"false_positive", "remediated", "retest_requested", "retest_passed",
		"retest_failed", "closed",
	}
	if len(FindingStatuses) != len(want) {
		t.Fatalf("FindingStatuses has %d entries, want %d", len(FindingStatuses), len(want))
	}
	for i, w := range want {
		if FindingStatuses[i] != w {
			t.Errorf("FindingStatuses[%d]=%q want %q", i, FindingStatuses[i], w)
		}
	}
}

func TestSeverityLevels_CanonicalOrder(t *testing.T) {
	t.Parallel()
	want := []string{"critical", "high", "medium", "low", "info"}
	for i, w := range want {
		if SeverityLevels[i] != w {
			t.Errorf("SeverityLevels[%d]=%q want %q (canonical order matters for ranking)", i, SeverityLevels[i], w)
		}
	}
}

func TestSeverityLevels_NoDuplicates(t *testing.T) {
	t.Parallel()
	seen := map[string]int{}
	for _, s := range SeverityLevels {
		seen[s]++
	}
	for s, n := range seen {
		if n > 1 {
			t.Errorf("severity %q appears %d times", s, n)
		}
	}
}

func TestFindingStatuses_AllLowercase(t *testing.T) {
	t.Parallel()
	for _, s := range FindingStatuses {
		for _, r := range s {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("FindingStatuses entry %q has uppercase", s)
			}
		}
	}
}

func TestAssetTypes_NonEmpty(t *testing.T) {
	t.Parallel()
	if len(AssetTypes) == 0 {
		t.Fatal("AssetTypes must not be empty")
	}
	// Sorted comparison so a reorder doesn't flake.
	sorted := append([]string(nil), AssetTypes...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			t.Errorf("duplicate asset type %q", sorted[i])
		}
	}
}

func TestCriticalityLevels_ExactSet(t *testing.T) {
	t.Parallel()
	want := []string{"critical", "high", "medium", "low", "unknown"}
	for i, w := range want {
		if CriticalityLevels[i] != w {
			t.Errorf("CriticalityLevels[%d]=%q want %q", i, CriticalityLevels[i], w)
		}
	}
}

// JSON-tag round-trip guards against accidental tag renames that would
// silently corrupt API responses. We pick the most-consumed types.
func TestUser_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	in := User{
		ID: uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		Email:      "x@y",
		FullName:   "X",
		MFAEnabled: true,
		Status:     "active",
		CreatedAt:  now,
	}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back User
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.Email != in.Email || back.FullName != in.FullName ||
		back.MFAEnabled != in.MFAEnabled || back.Status != in.Status {
		t.Errorf("User round-trip mismatch: %+v", back)
	}
}

func TestTenant_JSONFieldNames(t *testing.T) {
	t.Parallel()
	in := Tenant{
		ID: uuid.New(), PlatformID: uuid.New(), PartnerID: uuid.New(),
		Name: "Acme", Slug: "acme", Status: "active", IsolationMode: "shared",
	}
	out, _ := json.Marshal(in)
	js := string(out)
	for _, want := range []string{
		`"id":`, `"platform_id":`, `"partner_id":`, `"name":"Acme"`,
		`"slug":"acme"`, `"status":"active"`, `"isolation_mode":"shared"`,
	} {
		if !contains(js, want) {
			t.Errorf("Tenant JSON missing %q in %s", want, js)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
