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
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// gzipNewReader is a thin wrapper so the verify subcommand's
// helpers can stay short. The error-prone "wrap a file in a
// gzip.Reader" pattern lives here once.
func gzipNewReader(r io.Reader) (io.Reader, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return gz, nil
}

func main() {
	// Subcommand dispatch: `audit-bundle verify <bundle> -sign-key X`
	// re-checks every artifact's sha256 against manifest.json and
	// verifies bundle.sig HMAC. No DB required — the auditor runs
	// this against a bundle they were handed.
	if len(os.Args) >= 2 && os.Args[1] == "verify" {
		os.Args = os.Args[1:] // shift so flag.Parse() sees the subcommand args
		runVerify()
		return
	}

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

// ----- verify subcommand ------------------------------------------

// runVerify is the auditor-facing path. Run as:
//
//   audit-bundle verify path/to/bundle.tar.gz \
//     -sign-key <hex 32 bytes the operator gave you>
//
// It re-computes every artifact's sha256, compares against the
// manifest, verifies the HMAC signature, and prints a one-line
// verdict. Non-zero exit on any mismatch.
//
// Designed so an external auditor can run this without any
// VaultScan-specific tooling beyond a single statically-linked
// binary. No DB connection required.
func runVerify() {
	// Walk args manually so that -sign-key can appear before OR
	// after the positional bundle path. Go's flag package stops
	// parsing at the first non-flag arg, which would silently
	// drop the key if the user wrote `verify bundle.tar.gz -sign-key X`.
	var bundlePath, signKey string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-sign-key" || a == "--sign-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "audit-bundle verify: -sign-key requires a value")
				os.Exit(2)
			}
			signKey = args[i+1]
			i++
		case strings.HasPrefix(a, "-sign-key=") || strings.HasPrefix(a, "--sign-key="):
			signKey = a[strings.Index(a, "=")+1:]
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "audit-bundle verify: unknown flag %q\n", a)
			os.Exit(2)
		default:
			if bundlePath != "" {
				fmt.Fprintln(os.Stderr,
					"audit-bundle verify: only one positional <bundle.tar.gz> allowed")
				os.Exit(2)
			}
			bundlePath = a
		}
	}
	if bundlePath == "" {
		fmt.Fprintln(os.Stderr, "audit-bundle verify <bundle.tar.gz> [-sign-key HEX]")
		os.Exit(2)
	}
	f, err := os.Open(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle verify: open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	gz, err := newGzipReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle verify: gunzip: %v\n", err)
		os.Exit(1)
	}
	tr := tarReader(gz)
	files := readTarFiles(tr)

	manifestBody, ok := files["manifest.json"]
	if !ok {
		fmt.Fprintln(os.Stderr, "audit-bundle verify: bundle missing manifest.json")
		os.Exit(1)
	}
	var manifest struct {
		Artifacts []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
		GeneratedAt string `json:"generated_at"`
	}
	if err := jsonUnmarshal(manifestBody, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "audit-bundle verify: manifest not JSON: %v\n", err)
		os.Exit(1)
	}

	mismatches := 0
	for _, a := range manifest.Artifacts {
		body, present := files[a.Name]
		if !present {
			fmt.Fprintf(os.Stderr, "MISSING artifact: %s\n", a.Name)
			mismatches++
			continue
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if got != a.SHA256 {
			fmt.Fprintf(os.Stderr, "SHA256 MISMATCH for %s:\n  manifest=%s\n  actual  =%s\n",
				a.Name, a.SHA256, got)
			mismatches++
		}
	}

	// Verify HMAC if a key was supplied and bundle.sig present.
	sigBody, hasSig := files["bundle.sig"]
	if signKey != "" {
		if !hasSig {
			fmt.Fprintln(os.Stderr, "SIGNATURE: -sign-key supplied but bundle.sig not in bundle")
			mismatches++
		} else {
			key, kerr := hex.DecodeString(signKey)
			if kerr != nil || len(key) < 16 {
				fmt.Fprintln(os.Stderr, "SIGNATURE: -sign-key must be ≥16 bytes hex")
				os.Exit(2)
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(manifestBody)
			expected := hex.EncodeToString(mac.Sum(nil))
			got := strings.TrimSpace(string(sigBody))
			if !hmac.Equal([]byte(expected), []byte(got)) {
				fmt.Fprintf(os.Stderr, "SIGNATURE MISMATCH:\n  expected=%s\n  actual  =%s\n",
					expected, got)
				mismatches++
			}
		}
	} else if hasSig {
		fmt.Fprintln(os.Stderr,
			"NOTE: bundle.sig is present but no -sign-key supplied; signature NOT verified")
	}

	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "audit-bundle verify: FAIL (%d mismatch(es))\n", mismatches)
		os.Exit(1)
	}
	fmt.Printf("audit-bundle verify: OK (%d artifacts, generated_at=%s)\n",
		len(manifest.Artifacts), manifest.GeneratedAt)
}

// Small wrappers so the verify subcommand doesn't need to import
// archive/tar + compress/gzip + encoding/json explicitly (they're
// already imported by the build path above).
func newGzipReader(r io.Reader) (io.Reader, error)          { return gzipNewReader(r) }
func tarReader(r io.Reader) *tar.Reader                     { return tar.NewReader(r) }
func readTarFiles(tr *tar.Reader) map[string][]byte {
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		body, _ := io.ReadAll(tr)
		out[hdr.Name] = body
	}
	return out
}
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
