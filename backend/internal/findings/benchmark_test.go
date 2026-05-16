package findings

import (
	"testing"

	"github.com/google/uuid"
)

// Dedup fingerprint is computed on every ingested finding. Production
// scan results can land 50-100k findings in a single batch; a 10x
// regression here adds minutes to ingest. This benchmark pins the
// allocation count + ns/op so any future change to the hash inputs
// (or the fmt.Fprintf format string) shows up on the perf workflow.
func BenchmarkDedupFingerprint(b *testing.B) {
	asset := uuid.New()
	in := IngestInput{
		PlatformID:       uuid.New(),
		PartnerID:        uuid.New(),
		TenantID:         uuid.New(),
		EngagementID:     uuid.New(),
		AssetID:          &asset,
		Title:            "TLS 1.0 enabled on api.example.com",
		Scanner:          "testssl",
		AffectedEndpoint: "https://api.example.com:443",
		CVE:              "CVE-2024-1234",
		CWE:              "327",
		Port:             443,
		Protocol:         "tcp",
		Severity:         "high",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = dedupFingerprint(in)
	}
}

// BenchmarkDedupFingerprint_NoAsset covers the common path where the
// finding hasn't been correlated to an asset yet — the hot path during
// initial ingest before the asset-correlation pass runs.
func BenchmarkDedupFingerprint_NoAsset(b *testing.B) {
	in := IngestInput{
		PlatformID:       uuid.New(),
		PartnerID:        uuid.New(),
		TenantID:         uuid.New(),
		EngagementID:     uuid.New(),
		Title:            "X-Frame-Options missing",
		Scanner:          "zap",
		AffectedEndpoint: "https://api.example.com",
		CWE:              "1021",
		Port:             443,
		Protocol:         "tcp",
		Severity:         "low",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = dedupFingerprint(in)
	}
}
