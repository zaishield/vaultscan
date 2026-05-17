package partners

import (
	"strings"
	"testing"
)

func TestStarterPalette_Deterministic(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{"acme", "globex", "initech", "umbrella"} {
		p1, s1 := starterPalette(slug)
		p2, s2 := starterPalette(slug)
		if p1 != p2 || s1 != s2 {
			t.Errorf("slug %q: palette not stable across calls (%s,%s) vs (%s,%s)",
				slug, p1, s1, p2, s2)
		}
	}
}

func TestStarterPalette_DistinctSlugs(t *testing.T) {
	t.Parallel()
	// Different slugs SHOULD usually pick different palettes. With
	// 12 buckets and 4 inputs collisions are possible (~50%) but
	// we just check NOT ALL of them collide on bucket 0.
	seen := map[string]bool{}
	for _, slug := range []string{"acme", "globex", "initech", "umbrella", "stark", "wayne"} {
		p, _ := starterPalette(slug)
		seen[p] = true
	}
	if len(seen) < 2 {
		t.Errorf("6 different slugs collapsed to %d palettes; expected at least 2", len(seen))
	}
}

func TestStarterPalette_ValidHexColors(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{"a", "longer-slug-name", ""} {
		p, s := starterPalette(slug)
		for _, color := range []string{p, s} {
			if !strings.HasPrefix(color, "#") {
				t.Errorf("color %q missing #", color)
			}
			if len(color) != 7 {
				t.Errorf("color %q wrong length (want 7 chars incl #)", color)
			}
		}
	}
}

func TestStarterPalette_EmptySlugUsesBucketZero(t *testing.T) {
	t.Parallel()
	p, s := starterPalette("")
	if p != brandPalettes[0][0] || s != brandPalettes[0][1] {
		t.Errorf("empty slug should pick bucket 0, got (%s,%s)", p, s)
	}
}
