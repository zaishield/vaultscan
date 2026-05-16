package branding

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Branding asset validation runs on every partner upload. Bugs here
// mean attackers slip executable payloads (HTML, SVG with embedded JS)
// past the upload guard, or operators get false "config OK" reports
// for SPF / DMARC records that aren't actually enforcing.

func TestContentTypeAllowed_AllAssetTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		assetType, contentType string
		want                   bool
	}{
		{AssetLogoDark, "image/png", true},
		{AssetLogoDark, "image/svg+xml", true},
		{AssetLogoDark, "image/jpeg", false}, // not in allow list for logo
		{AssetLogoLight, "image/webp", true},
		{AssetFavicon, "image/x-icon", true},
		{AssetFavicon, "image/svg+xml", true},
		{AssetFavicon, "image/webp", false}, // webp not in favicon list
		{AssetPDFCover, "application/pdf", true},
		{AssetPDFCover, "image/jpeg", true},
		{AssetWatermark, "image/svg+xml", true},
		{AssetWatermark, "application/pdf", false},
		// charset suffix on the content type must be ignored
		{AssetLogoDark, "image/png; charset=utf-8", true},
		// case-insensitive
		{AssetLogoDark, "IMAGE/PNG", true},
		// XSS attempt: text/html must always be refused
		{AssetLogoDark, "text/html", false},
		{AssetFavicon, "text/html", false},
		// Unknown asset type → reject regardless of CT
		{"unknown_asset", "image/png", false},
	}
	for _, tc := range cases {
		got := contentTypeAllowed(tc.assetType, tc.contentType)
		if got != tc.want {
			t.Errorf("contentTypeAllowed(%q, %q)=%v want %v",
				tc.assetType, tc.contentType, got, tc.want)
		}
	}
}

func TestClassifySPF(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"v=spf1 include:_spf.google.com -all":     "pass",
		"v=spf1 include:_spf.google.com ~all":     "pass",
		"v=spf1 include:_spf.google.com +all":     "misconfigured", // +all = permissive
		"v=spf1":                                   "misconfigured",
		"":                                         "misconfigured",
		"V=SPF1 INCLUDE:X -ALL":                    "pass", // case-insensitive
		"v=spf1 redirect=_spf.example.com":         "misconfigured",
	}
	for r, want := range cases {
		if got := classifySPF(r); got != want {
			t.Errorf("classifySPF(%q)=%q want %q", r, got, want)
		}
	}
}

func TestClassifyDMARC(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"v=DMARC1; p=reject":               "pass",
		"v=DMARC1; p=quarantine":           "pass",
		"v=DMARC1; p=none":                 "monitor",
		"v=DMARC1":                         "misconfigured", // no p=
		"":                                 "misconfigured",
		"v=DMARC1; P=Reject; rua=mailto:x": "pass", // case-insensitive
	}
	for r, want := range cases {
		if got := classifyDMARC(r); got != want {
			t.Errorf("classifyDMARC(%q)=%q want %q", r, got, want)
		}
	}
}

func TestNewETag_DeterministicAndSensitiveToInputs(t *testing.T) {
	t.Parallel()
	pid := uuid.New()
	at := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	e1 := newETag(pid, at)
	e2 := newETag(pid, at)
	if e1 != e2 {
		t.Errorf("ETag not deterministic for same inputs: %s vs %s", e1, e2)
	}
	// Different time → different ETag
	if newETag(pid, at.Add(time.Second)) == e1 {
		t.Error("ETag must change when timestamp changes")
	}
	// Different partner → different ETag
	if newETag(uuid.New(), at) == e1 {
		t.Error("ETag must change when partner changes")
	}
	// ETag shape: looks like a hex-ish opaque string, non-empty
	if e1 == "" || strings.ContainsAny(e1, "\n\r ") {
		t.Errorf("ETag malformed: %q", e1)
	}
}

func TestInSlice(t *testing.T) {
	t.Parallel()
	if !inSlice([]string{"a", "b"}, "b") {
		t.Error("inSlice should find 'b'")
	}
	if inSlice([]string{"a", "b"}, "c") {
		t.Error("inSlice should NOT find 'c'")
	}
	if inSlice(nil, "x") {
		t.Error("inSlice on nil slice should return false")
	}
}

func TestNullIfEmpty_PassthroughAndNull(t *testing.T) {
	t.Parallel()
	if v := nullIfEmpty(""); v != nil {
		t.Errorf("nullIfEmpty(\"\")=%v want nil", v)
	}
	if v := nullIfEmpty("x"); v != "x" {
		t.Errorf("nullIfEmpty(\"x\")=%v want \"x\"", v)
	}
}

// Property: classifySPF + classifyDMARC must be pure functions — same
// input must yield identical output across many calls.
func FuzzClassifySPF(f *testing.F) {
	f.Add("v=spf1 -all")
	f.Add("")
	f.Add("anything ~all")
	f.Fuzz(func(t *testing.T, in string) {
		a := classifySPF(in)
		b := classifySPF(in)
		if a != b {
			t.Fatalf("classifySPF not deterministic: %q vs %q for %q", a, b, in)
		}
		// Output must be in the closed set { pass, misconfigured }
		if a != "pass" && a != "misconfigured" {
			t.Fatalf("classifySPF returned %q outside closed set", a)
		}
	})
}

func FuzzClassifyDMARC(f *testing.F) {
	f.Add("v=DMARC1; p=reject")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		got := classifyDMARC(in)
		if got != "pass" && got != "monitor" && got != "misconfigured" {
			t.Fatalf("classifyDMARC returned %q outside closed set", got)
		}
	})
}
