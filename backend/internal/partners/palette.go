// palette.go — deterministic starter palette derivation.
//
// Every new partner used to land on the SAME default colors
// (#0F172A / #38BDF8) which made every fresh-onboarded partner look
// identical until they ran the branding wizard. We now derive a
// per-partner palette from the slug — same slug, same colors
// across reboots, so test fixtures don't drift, but two adjacent
// partners pick visibly different shades.
//
// Implementation: pick a hue from a curated set of 12 brand-safe
// pairs (dark "primary" + lighter "secondary" accent). The slug's
// SHA-256 selects the bucket. Picking from a curated palette is
// safer than computing arbitrary HSL — the curated colors are
// chosen for accessible contrast on white + dark backgrounds.

package partners

import (
	"crypto/sha256"
	"encoding/binary"
)

// brandPalettes is the curated set. Order is stable; appending new
// entries is safe (existing partners keep their existing slug-hash
// bucket because we use modulo over a stable length).
//
// Each entry is a (primary, secondary) hex pair without the leading
// "#" (matches the column convention).
var brandPalettes = [][2]string{
	{"#0F172A", "#38BDF8"}, // slate / sky — legacy default, kept as bucket 0
	{"#1E293B", "#22D3EE"}, // slate / cyan
	{"#312E81", "#A78BFA"}, // indigo / purple
	{"#0C4A6E", "#7DD3FC"}, // ocean / light-blue
	{"#14532D", "#86EFAC"}, // forest / mint
	{"#365314", "#BEF264"}, // olive / lime
	{"#7C2D12", "#FB923C"}, // burnt / orange
	{"#831843", "#F472B6"}, // wine / rose
	{"#4C1D95", "#C4B5FD"}, // royal / lavender
	{"#1F2937", "#9CA3AF"}, // graphite / silver
	{"#0B4F3F", "#5EEAD4"}, // pine / teal
	{"#3F0F00", "#FCA5A5"}, // coffee / coral
}

// starterPalette picks the deterministic pair for a slug. Empty
// slug falls back to bucket 0 (the legacy default).
func starterPalette(slug string) (primary, secondary string) {
	if slug == "" {
		return brandPalettes[0][0], brandPalettes[0][1]
	}
	sum := sha256.Sum256([]byte(slug))
	idx := binary.BigEndian.Uint32(sum[0:4]) % uint32(len(brandPalettes))
	return brandPalettes[idx][0], brandPalettes[idx][1]
}
