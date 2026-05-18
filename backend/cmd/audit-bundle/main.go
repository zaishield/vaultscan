// cmd/audit-bundle assembles the per-quarter forensic evidence
// bundle that SOC 2 (CC4.1 / CC7.2) and ISO 27001 audits expect.
// Output is a tar.gz containing:
//
//   manifest.json          — summary + SHA-256 of every artifact
//   verify_deep.json       — most recent full VerifyDeep result
//   chain_breaks.json      — every audit_chain_breaks row (empty
//                            if the chain never broke — which IS
//                            the desired state for an audit)
//   verification_checkpoints.json — incremental verifier cursor +
//                                   rows_verified_total counter
//   tenant_data_keys_inventory.json — per-tenant DEK metadata:
//                                     kek_id, key_version, retired_at
//                                     (NO key material; ids only)
//   retention_policies.json — what the retention sweeper enforces
//   bundle.sig             — HMAC-SHA256 of manifest.json under
//                            VAULTSCAN_BUNDLE_SIGNING_KEY (operator
//                            stores the key out-of-band; auditors
//                            verify by recomputing)
//
// The bundle is INTENDED to be safe to share with an external
// auditor: it contains no tenant payloads, no user PII, no key
// material — only the integrity-check artifacts that prove the
// audit chain functioned correctly during the period.
//
// Usage:
//   audit-bundle -db $DATABASE_URL -output /tmp/q1-2026.tar.gz
//   audit-bundle -db $DATABASE_URL -sign-key $(openssl rand -hex 32) -output bundle.tar.gz
//
// Designed to be run from a privileged operator host; do NOT
// expose this binary's surface via the public API.

package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

func main() {
	dbURL := flag.String("db", "", "Postgres URL (or set VAULTSCAN_DATABASE_URL)")
	outPath := flag.String("output", "", "where to write the bundle tar.gz")
	signKey := flag.String("sign-key", "", "hex-encoded HMAC key (32 bytes) for bundle.sig; if omitted, bundle.sig is not produced")
	flag.Parse()

	if *dbURL == "" {
		*dbURL = os.Getenv("VAULTSCAN_DATABASE_URL")
	}
	if *dbURL == "" {
		fmt.Fprintln(os.Stderr, "audit-bundle: -db or VAULTSCAN_DATABASE_URL is required")
		os.Exit(2)
	}
	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "audit-bundle: -output is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle: connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	bundle, err := buildBundle(ctx, pool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle: build: %v\n", err)
		os.Exit(1)
	}

	if *signKey != "" {
		key, err := hex.DecodeString(*signKey)
		if err != nil || len(key) < 16 {
			fmt.Fprintln(os.Stderr, "audit-bundle: -sign-key must be ≥16 bytes hex-encoded")
			os.Exit(2)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(bundle.manifestJSON)
		bundle.signatureHex = hex.EncodeToString(mac.Sum(nil))
	}

	if err := writeTarGz(*outPath, bundle); err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle: write: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("audit-bundle: wrote %s\n", *outPath)
	fmt.Printf("audit-bundle: manifest_sha256=%s\n", bundle.manifestSHA)
	if bundle.signatureHex != "" {
		fmt.Printf("audit-bundle: signature=%s\n", bundle.signatureHex)
	}
}

type bundleArtifact struct {
	name      string
	bodyJSON  []byte
	sha256Hex string
}

type assembledBundle struct {
	generatedAt  time.Time
	artifacts    []bundleArtifact
	manifestJSON []byte
	manifestSHA  string
	signatureHex string
}

type chainBreak struct {
	ID         int64     `json:"id"`
	FirstBadID int64     `json:"first_bad_id"`
	LastGoodID int64     `json:"last_good_id"`
	Detail     string    `json:"detail"`
	DetectedAt time.Time `json:"detected_at"`
}

type verificationCheckpoint struct {
	LastVerifiedID    int64     `json:"last_verified_id"`
	LastVerifiedHash  string    `json:"last_verified_hash_hex"`
	LastVerifiedAt    time.Time `json:"last_verified_at"`
	RowsVerifiedTotal int64     `json:"rows_verified_total"`
}

type tenantDEK struct {
	TenantID   string     `json:"tenant_id"`
	KeyVersion int        `json:"key_version"`
	KekID      string     `json:"kek_id"`
	CreatedAt  time.Time  `json:"created_at"`
	RetiredAt  *time.Time `json:"retired_at,omitempty"`
}

type retentionPolicy struct {
	EventPrefix   string `json:"event_prefix"`
	RetentionDays int    `json:"retention_days"`
}

func buildBundle(ctx context.Context, pool *pgxpool.Pool) (*assembledBundle, error) {
	out := &assembledBundle{generatedAt: time.Now().UTC()}

	// 1. VerifyDeep — the headline artifact.
	auditSvc := audit.New(pool)
	verifyRes, err := auditSvc.VerifyDeep(ctx)
	if err != nil {
		return nil, fmt.Errorf("VerifyDeep: %w", err)
	}
	if err := out.addJSON("verify_deep.json", verifyRes); err != nil {
		return nil, err
	}

	// 2. Audit chain breaks — every detected break in the period.
	breaks, err := listChainBreaks(ctx, pool)
	if err != nil {
		return nil, err
	}
	if err := out.addJSON("chain_breaks.json", breaks); err != nil {
		return nil, err
	}

	// 3. Verification checkpoint — proves the cron actually ran.
	ckpt, err := readCheckpoint(ctx, pool)
	if err != nil {
		return nil, err
	}
	if err := out.addJSON("verification_checkpoints.json", ckpt); err != nil {
		return nil, err
	}

	// 4. Tenant DEK inventory — metadata only.
	deks, err := listTenantDEKs(ctx, pool)
	if err != nil {
		return nil, err
	}
	if err := out.addJSON("tenant_data_keys_inventory.json", deks); err != nil {
		return nil, err
	}

	// 5. Retention policies — what the sweeper enforces.
	policies, err := listRetentionPolicies(ctx, pool)
	if err != nil {
		return nil, err
	}
	if err := out.addJSON("retention_policies.json", policies); err != nil {
		return nil, err
	}

	// 6. Manifest is built from the artifacts' sha256s — auditors
	// recompute each artifact's sha256, compare against manifest.
	manifest := map[string]any{
		"generated_at": out.generatedAt.Format(time.RFC3339Nano),
		"artifacts": func() []map[string]string {
			rows := make([]map[string]string, 0, len(out.artifacts))
			for _, a := range out.artifacts {
				rows = append(rows, map[string]string{
					"name":   a.name,
					"sha256": a.sha256Hex,
				})
			}
			return rows
		}(),
		"verify_deep_first_bad_id": verifyRes.FirstBadID,
		"verify_deep_total_rows":   verifyRes.Total,
		"chain_break_count":        len(breaks),
		"tenant_dek_count":         len(deks),
	}
	mj, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	out.manifestJSON = mj
	sum := sha256.Sum256(mj)
	out.manifestSHA = hex.EncodeToString(sum[:])
	return out, nil
}

func (b *assembledBundle) addJSON(name string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: marshal: %w", name, err)
	}
	sum := sha256.Sum256(body)
	b.artifacts = append(b.artifacts, bundleArtifact{
		name: name, bodyJSON: body, sha256Hex: hex.EncodeToString(sum[:]),
	})
	return nil
}

func listChainBreaks(ctx context.Context, pool *pgxpool.Pool) ([]chainBreak, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, first_bad_id, last_good_id, COALESCE(detail,''), detected_at
		  FROM audit_chain_breaks
		 ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []chainBreak{}
	for rows.Next() {
		var b chainBreak
		if err := rows.Scan(&b.ID, &b.FirstBadID, &b.LastGoodID, &b.Detail, &b.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func readCheckpoint(ctx context.Context, pool *pgxpool.Pool) (*verificationCheckpoint, error) {
	var c verificationCheckpoint
	var hash []byte
	err := pool.QueryRow(ctx, `
		SELECT last_verified_id, last_verified_hash, last_verified_at, rows_verified_total
		  FROM audit_chain_verification_checkpoints
		 WHERE id = 1`).
		Scan(&c.LastVerifiedID, &hash, &c.LastVerifiedAt, &c.RowsVerifiedTotal)
	if err != nil {
		return nil, err
	}
	c.LastVerifiedHash = hex.EncodeToString(hash)
	return &c, nil
}

func listTenantDEKs(ctx context.Context, pool *pgxpool.Pool) ([]tenantDEK, error) {
	rows, err := pool.Query(ctx, `
		SELECT tenant_id::text, key_version, kek_id, created_at, retired_at
		  FROM tenant_data_keys
		 ORDER BY tenant_id, key_version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []tenantDEK{}
	for rows.Next() {
		var t tenantDEK
		if err := rows.Scan(&t.TenantID, &t.KeyVersion, &t.KekID, &t.CreatedAt, &t.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func listRetentionPolicies(ctx context.Context, pool *pgxpool.Pool) ([]retentionPolicy, error) {
	rows, err := pool.Query(ctx, `
		SELECT event_prefix, retention_days FROM audit_retention_policies
		 ORDER BY length(event_prefix) DESC`)
	if err != nil {
		// Table may not exist on older deployments — surface as
		// empty list, not a fatal error. Auditor still sees the
		// other artifacts.
		return []retentionPolicy{}, nil
	}
	defer rows.Close()
	out := []retentionPolicy{}
	for rows.Next() {
		var p retentionPolicy
		if err := rows.Scan(&p.EventPrefix, &p.RetentionDays); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func writeTarGz(path string, b *assembledBundle) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, a := range b.artifacts {
		if err := writeTarFile(tw, a.name, a.bodyJSON); err != nil {
			return err
		}
	}
	if err := writeTarFile(tw, "manifest.json", b.manifestJSON); err != nil {
		return err
	}
	if b.signatureHex != "" {
		if err := writeTarFile(tw, "bundle.sig", []byte(b.signatureHex)); err != nil {
			return err
		}
	}
	return nil
}

func writeTarFile(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{
		Name: name, Size: int64(len(body)),
		Mode: 0o644, ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}
