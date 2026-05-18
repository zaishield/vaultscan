package evidence

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/observability"
)

// evidenceLogger surfaces the partial-failure cases that the
// rotation + sweeper loops would otherwise silently swallow. The
// "log-and-continue" comments in the loops below promise visibility
// in operator logs — this is what fulfils that promise. Metrics
// scrapers tagged `component=evidence` and `op=rewrap` count the
// drops; alerting on a non-zero rate is the recommended cron-health
// signal.
var evidenceLogger = zerolog.New(os.Stderr).With().
	Timestamp().Str("component", "evidence").Logger()

// ---------------- Envelope encryption ---------------------------------------
//
// The KEK is the existing v.masterKey (32 bytes). The DEK is a fresh random
// 32-byte key per tenant, wrapped with AES-256-GCM under the KEK and
// persisted in tenant_data_keys. wrapped_key in the DB is nonce || GCM ct.

// EnsureTenantKey returns the current (latest, non-retired) DEK version
// for a tenant. Creates one on first call.
func (v *Vault) EnsureTenantKey(ctx context.Context, tenantID uuid.UUID) (int, []byte, error) {
	if version, dek, err := v.currentTenantKey(ctx, tenantID); err == nil {
		return version, dek, nil
	}
	// Generate + wrap a new DEK.
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return 0, nil, err
	}
	wrapped, err := v.wrap(dek)
	if err != nil {
		return 0, nil, err
	}
	var version int
	if err := v.pool.QueryRow(ctx, `
		INSERT INTO tenant_data_keys(tenant_id, key_version, wrapped_key, kek_id)
		VALUES ($1, 1, $2, $3)
		RETURNING key_version`,
		tenantID, wrapped, v.kekIDForWrite()).Scan(&version); err != nil {
		return 0, nil, err
	}
	return version, dek, nil
}

// ReWrapTenantObjects re-encrypts every object sealed under an older
// DEK version with the tenant's CURRENT (highest) version. The blob
// is fetched, decrypted under its current key version, then re-
// encrypted under the latest version. The DB row is updated to
// reflect the new version. On success the storage object is
// overwritten in-place — same key path, new bytes.
//
// This is the "real" rotation half: RotateTenantKey just writes a
// fresh DEK row going forward; ReWrapTenantObjects is what
// regulators and SOC2 auditors expect when they ask "did you
// actually re-encrypt the data on rotation, or just stop using the
// old key for new data?"
//
// Bounded by `maxBatch` per call so a cron tick can't pin the
// process for an hour on a tenant with millions of evidence rows.
// Returns the number of objects re-wrapped + an "more" boolean
// indicating whether subsequent calls would do further work.
func (v *Vault) ReWrapTenantObjects(ctx context.Context, tenantID uuid.UUID, maxBatch int) (rewrapped int, more bool, err error) {
	if maxBatch <= 0 {
		maxBatch = 100
	}
	currentVer, _, err := v.currentTenantKey(ctx, tenantID)
	if err != nil {
		return 0, false, fmt.Errorf("evidence.ReWrapTenantObjects: current key: %w", err)
	}
	// Pull (id, key_version, storage_url) for objects whose key
	// version is below current. LIMIT maxBatch+1 so we can detect
	// "more available" without a second count query.
	rows, err := v.pool.Query(ctx, `
		SELECT id, encryption_key_version
		  FROM finding_evidence
		 WHERE tenant_id = $1
		   AND encrypted = true
		   AND encryption_key_version IS NOT NULL
		   AND encryption_key_version < $2
		 ORDER BY uploaded_at ASC
		 LIMIT $3`, tenantID, currentVer, maxBatch+1)
	if err != nil {
		return 0, false, err
	}
	type rowInfo struct {
		id  uuid.UUID
		ver int
	}
	var todo []rowInfo
	for rows.Next() {
		var ri rowInfo
		if err := rows.Scan(&ri.id, &ri.ver); err != nil {
			rows.Close()
			return 0, false, err
		}
		todo = append(todo, ri)
	}
	rows.Close()
	more = len(todo) > maxBatch
	if more {
		todo = todo[:maxBatch]
	}
	var skipped int
	for _, ri := range todo {
		if err := v.rewrapOne(ctx, tenantID, ri.id, ri.ver, currentVer); err != nil {
			// Log-and-continue: a single broken blob shouldn't pin
			// the rotation forever. The next sweep will retry.
			// Emit a structured warn so cron-health scrapers can
			// alert on a non-zero rate.
			evidenceLogger.Warn().
				Err(err).
				Str("op", "rewrap").
				Str("tenant_id", tenantID.String()).
				Str("evidence_id", ri.id.String()).
				Int("from_version", ri.ver).
				Int("to_version", currentVer).
				Msg("evidence rewrap skipped a blob")
			skipped++
			continue
		}
		rewrapped++
	}
	if skipped > 0 {
		evidenceLogger.Warn().
			Str("op", "rewrap").
			Str("tenant_id", tenantID.String()).
			Int("skipped", skipped).
			Int("rewrapped", rewrapped).
			Msg("evidence rewrap completed with partial failures")
	}
	return rewrapped, more, nil
}

func (v *Vault) rewrapOne(ctx context.Context, tenantID, evidenceID uuid.UUID, oldVer, newVer int) error {
	// The storage object UUID is distinct from the evidence row id
	// (PutWithDEK mints a fresh UUID for the blob path). Resolve it
	// via the row's storage_url so Get / Put hit the right file.
	var storageURL string
	if err := v.pool.QueryRow(ctx,
		`SELECT storage_url FROM finding_evidence WHERE id = $1`, evidenceID).
		Scan(&storageURL); err != nil {
		return fmt.Errorf("rewrap: lookup storage_url: %w", err)
	}
	stTenant, stObject, ok := parseObjectURL(storageURL)
	if !ok || stTenant != tenantID {
		return errors.New("rewrap: bad storage_url")
	}
	raw, err := v.storage.Get(ctx, stTenant, stObject)
	if err != nil {
		return fmt.Errorf("rewrap: get: %w", err)
	}
	if len(raw) < 12 {
		return errors.New("rewrap: blob too short for nonce")
	}
	oldDEK, err := v.tenantKeyByVersion(ctx, tenantID, oldVer)
	if err != nil {
		return fmt.Errorf("rewrap: load old DEK v%d: %w", oldVer, err)
	}
	plain, err := decryptWithDEK(oldDEK, raw[12:], raw[:12])
	if err != nil {
		return fmt.Errorf("rewrap: decrypt: %w", err)
	}
	// Encrypt under the new version (look it up freshly each call
	// so a rotation midway through doesn't pin us to a stale key).
	_, newDEK, err := v.currentTenantKey(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("rewrap: load new DEK: %w", err)
	}
	ct, nonce, err := encryptWithDEK(newDEK, plain)
	if err != nil {
		return fmt.Errorf("rewrap: encrypt: %w", err)
	}
	if err := v.storage.Put(ctx, stTenant, stObject, append(nonce, ct...)); err != nil {
		return fmt.Errorf("rewrap: put: %w", err)
	}
	if _, err := v.pool.Exec(ctx,
		`UPDATE finding_evidence SET encryption_key_version = $2 WHERE id = $1`,
		evidenceID, newVer); err != nil {
		return fmt.Errorf("rewrap: update row: %w", err)
	}
	_ = v.recordCustody(ctx, evidenceID, "rewrapped", nil, "system", nil, "", map[string]any{
		"from_version": oldVer, "to_version": newVer,
	})
	return nil
}

// RotateStaleTenantKeys finds every tenant whose latest DEK is older
// than `maxAge` and rotates them. Returns the count of tenants
// rotated. Designed to be called from a cron job — cheap when nothing
// is due, idempotent if interrupted (the per-tenant rotation is its
// own transaction; partial progress survives).
//
// Rotation cadence guidance: 90 days is a common SOC2 / ISO27001
// target for key material. Daily cron + max_age=90 days means at
// most one tenant rotates per day in steady state.
func (v *Vault) RotateStaleTenantKeys(ctx context.Context, maxAge time.Duration) (int, error) {
	rows, err := v.pool.Query(ctx, `
		SELECT tenant_id FROM (
		    SELECT tenant_id, MAX(created_at) AS latest
		      FROM tenant_data_keys
		     WHERE retired_at IS NULL
		     GROUP BY tenant_id
		) t
		WHERE latest < now() - $1::interval`, fmt.Sprintf("%d seconds", int(maxAge.Seconds())))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var tenantIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		tenantIDs = append(tenantIDs, id)
	}
	rotated := 0
	for _, id := range tenantIDs {
		if _, err := v.RotateTenantKey(ctx, id); err != nil {
			// Log-and-continue: one tenant's failure shouldn't
			// block the sweep — next tick retries. Emit a
			// structured warn so the operator sees the per-
			// tenant failure rate, not just the sweep total.
			evidenceLogger.Warn().
				Err(err).
				Str("op", "rotate_stale").
				Str("tenant_id", id.String()).
				Msg("tenant DEK rotation skipped")
			continue
		}
		rotated++
	}
	return rotated, nil
}

// RotateTenantKey writes a new DEK version. Old objects keep their
// old encryption_key_version so they remain decryptable.
func (v *Vault) RotateTenantKey(ctx context.Context, tenantID uuid.UUID) (int, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return 0, err
	}
	wrapped, err := v.wrap(dek)
	if err != nil {
		return 0, err
	}
	var version int
	err = v.pool.QueryRow(ctx, `
		INSERT INTO tenant_data_keys(tenant_id, key_version, wrapped_key, kek_id)
		SELECT $1, COALESCE(max(key_version),0)+1, $2, $3
		  FROM tenant_data_keys WHERE tenant_id=$1
		RETURNING key_version`, tenantID, wrapped, v.kekIDForWrite()).Scan(&version)
	return version, err
}

// kekIDForWrite returns the kek_id string stamped on newly-wrapped
// tenant_data_keys rows. Defaults to "platform-master-v1" if no
// WithActiveKEKID option was supplied — preserves backwards
// compatibility with deployments that haven't yet rotated.
func (v *Vault) kekIDForWrite() string {
	if v.activeKEKID == "" {
		return "platform-master-v1"
	}
	return v.activeKEKID
}

// RewrapTenantDEKsToActiveKEK is the operator-driven rotation
// drain. It scans tenant_data_keys for rows whose kek_id !=
// the active id, unwraps each (which transparently uses the
// retired KEK via v.previousMasterKeys fallback), re-wraps under
// the active KEK, and updates the row's wrapped_key + kek_id.
//
// Bounded per call by maxBatch so an operator running this on a
// 100k-tenant deployment can chunk the work + measure progress.
// Returns (rewrapped, more, err); more=true means subsequent
// calls would advance.
//
// Safety:
//   - Idempotent: a row already under the active KEK is skipped.
//   - Per-row transaction: a single corrupt row doesn't fail the
//     whole batch.
//   - The retired KEK material MUST still be configured (via
//     WithPreviousMasterKeys) when this method runs. Drop it from
//     config ONLY after the sweep has converged (more=false on
//     two consecutive runs).
func (v *Vault) RewrapTenantDEKsToActiveKEK(ctx context.Context, maxBatch int) (rewrapped int, more bool, err error) {
	if maxBatch <= 0 {
		maxBatch = 100
	}
	active := v.kekIDForWrite()
	rows, err := v.pool.Query(ctx, `
		SELECT tenant_id, key_version, wrapped_key
		  FROM tenant_data_keys
		 WHERE kek_id != $1
		   AND retired_at IS NULL
		 ORDER BY tenant_id, key_version
		 LIMIT $2`, active, maxBatch+1)
	if err != nil {
		return 0, false, fmt.Errorf("evidence.RewrapTenantDEKsToActiveKEK: query: %w", err)
	}
	type row struct {
		tenantID uuid.UUID
		version  int
		wrapped  []byte
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenantID, &r.version, &r.wrapped); err != nil {
			rows.Close()
			return 0, false, err
		}
		todo = append(todo, r)
	}
	rows.Close()
	more = len(todo) > maxBatch
	if more {
		todo = todo[:maxBatch]
	}
	for _, r := range todo {
		dek, err := v.unwrap(r.wrapped)
		if err != nil {
			evidenceLogger.Warn().
				Err(err).
				Str("op", "rewrap_dek").
				Str("tenant_id", r.tenantID.String()).
				Int("version", r.version).
				Msg("DEK unwrap failed during KEK rotation sweep — likely retired KEK is missing from config")
			continue
		}
		rewrapped_blob, err := v.wrap(dek)
		if err != nil {
			evidenceLogger.Warn().
				Err(err).
				Str("op", "rewrap_dek").
				Str("tenant_id", r.tenantID.String()).
				Msg("DEK re-wrap failed under active KEK")
			continue
		}
		if _, err := v.pool.Exec(ctx, `
			UPDATE tenant_data_keys
			   SET wrapped_key = $3, kek_id = $4
			 WHERE tenant_id = $1 AND key_version = $2`,
			r.tenantID, r.version, rewrapped_blob, active); err != nil {
			evidenceLogger.Warn().
				Err(err).
				Str("op", "rewrap_dek").
				Str("tenant_id", r.tenantID.String()).
				Msg("UPDATE tenant_data_keys failed after re-wrap")
			continue
		}
		rewrapped++
	}
	return rewrapped, more, nil
}

// currentTenantKey returns the latest DEK (highest version not retired).
func (v *Vault) currentTenantKey(ctx context.Context, tenantID uuid.UUID) (int, []byte, error) {
	var version int
	var wrapped []byte
	err := v.pool.QueryRow(ctx, `
		SELECT key_version, wrapped_key
		  FROM tenant_data_keys
		 WHERE tenant_id=$1 AND retired_at IS NULL
		 ORDER BY key_version DESC LIMIT 1`, tenantID).Scan(&version, &wrapped)
	if err != nil {
		return 0, nil, err
	}
	dek, err := v.unwrap(wrapped)
	if err != nil {
		return 0, nil, err
	}
	return version, dek, nil
}

func (v *Vault) tenantKeyByVersion(ctx context.Context, tenantID uuid.UUID, version int) ([]byte, error) {
	var wrapped []byte
	err := v.pool.QueryRow(ctx, `
		SELECT wrapped_key FROM tenant_data_keys
		 WHERE tenant_id=$1 AND key_version=$2`, tenantID, version).Scan(&wrapped)
	if err != nil {
		return nil, err
	}
	return v.unwrap(wrapped)
}

// WrapBytes is the exported helper that other packages (integrations,
// notify) use to seal small secrets under the master KEK. Returns
// the sealed blob + a synthetic version (always 1 — these secrets are
// KEK-only, not per-tenant DEK). Callers store the blob in a BYTEA
// column and call UnwrapBlob to read.
func (v *Vault) WrapBytes(ctx context.Context, plain []byte) ([]byte, int, error) {
	_ = ctx // reserved for future async KMS path
	b, err := v.wrap(plain)
	if err != nil {
		return nil, 0, err
	}
	return b, 1, nil
}

// UnwrapBlob is the inverse of WrapBytes.
func (v *Vault) UnwrapBlob(ctx context.Context, blob []byte) ([]byte, error) {
	_ = ctx
	return v.unwrap(blob)
}

func (v *Vault) wrap(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, ct...), nil
}

func (v *Vault) unwrap(blob []byte) ([]byte, error) {
	// Try the active KEK first — the hot path on a non-rotating
	// deployment. On AEAD-auth failure, fall through to each
	// retired KEK in order. This is the rotation window:
	// previously-wrapped DEKs decrypt under the old key, and
	// RewrapTenantDEKsToActiveKEK re-wraps them under the new
	// active KEK at operator pace.
	if pt, err := unwrapWith(v.masterKey, blob); err == nil {
		return pt, nil
	}
	for i, k := range v.previousMasterKeys {
		if len(k) == 0 {
			continue
		}
		if pt, err := unwrapWith(k, blob); err == nil {
			return pt, nil
		}
		// Track which old key handled which blob — useful operator
		// signal during rotation. We don't return early on success
		// per-key; the caller (Read*) doesn't need the index.
		_ = i
	}
	return nil, errors.New("evidence: unwrap failed against active + all retired KEKs")
}

func unwrapWith(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("evidence: wrapped key blob too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// encryptWithDEK and decryptWithDEK mirror the legacy master-key path but
// operate against an arbitrary 32-byte key.
func encryptWithDEK(dek, plain []byte) (ct, nonce []byte, err error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plain, nil), nonce, nil
}

func decryptWithDEK(dek, ct, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// PutWithDEK stores the object encrypted under the tenant's current DEK.
// Returns the storage URL + the key version used.
func (v *Vault) PutWithDEK(ctx context.Context, tenantID uuid.UUID, body []byte) (string, int, error) {
	version, dek, err := v.EnsureTenantKey(ctx, tenantID)
	if err != nil {
		return "", 0, err
	}
	ct, nonce, err := encryptWithDEK(dek, body)
	if err != nil {
		return "", 0, err
	}
	id := uuid.New()
	if err := v.storage.Put(ctx, tenantID, id, append(nonce, ct...)); err != nil {
		return "", 0, fmt.Errorf("evidence: storage.Put: %w", err)
	}
	return objectURL(tenantID, id), version, nil
}

// RecordWithDEK is like Record but uses the tenant DEK envelope.
func (v *Vault) RecordWithDEK(ctx context.Context, in PutInput) (id uuid.UUID, err error) {
	ctx, end := observability.Span(ctx, "evidence.RecordWithDEK",
		"tenant_id", in.TenantID.String(),
		"kind", in.Kind,
		"content_type", in.ContentType,
	)
	defer func() { end(err) }()
	// Data-residency gate. Evidence is the long-lived state with the
	// strongest residency exposure (contains scan output, screenshots,
	// PII). A residency violation here aborts before any bytes touch
	// object storage or the DB.
	if v.residency != nil && v.podRegion != "" {
		if err := v.residency.CheckResidency(ctx, in.TenantID, v.podRegion); err != nil {
			return uuid.Nil, err
		}
	}
	storageURL, version, err := v.PutWithDEK(ctx, in.TenantID, in.Body)
	if err != nil {
		return uuid.Nil, err
	}
	digest := sha256.Sum256(in.Body)
	hashHex := hex.EncodeToString(digest[:])
	id = uuid.New()
	if _, execErr := v.pool.Exec(ctx, `
		INSERT INTO finding_evidence(id, tenant_id, partner_id, finding_id, engagement_id,
		    scan_job_id, evidence_type, storage_url, sha256, size_bytes, content_type,
		    encrypted, encryption_key_version, uploaded_by, uploaded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12,$13, now())`,
		id, in.TenantID, in.PartnerID, in.FindingID, in.EngagementID, in.ScanJobID,
		in.Kind, storageURL, hashHex, int64(len(in.Body)), in.ContentType,
		version, in.UploadedBy); execErr != nil {
		return uuid.Nil, fmt.Errorf("evidence: insert: %w", execErr)
	}
	_ = v.recordCustody(ctx, id, "uploaded", in.UploadedBy, "user", nil, "", map[string]any{
		"sha256": hashHex, "size": len(in.Body), "key_version": version, "kind": in.Kind,
	})
	return id, nil
}

// ReadWithDEK reads an evidence object using whichever DEK version sealed
// it. Falls back to the legacy master-key decrypt when the version is NULL
// (objects from before VS-08).
func (v *Vault) ReadWithDEK(ctx context.Context, evidenceID uuid.UUID, actor *uuid.UUID, ip net.IP, ua string) ([]byte, error) {
	var (
		tenantID   uuid.UUID
		storageURL string
		keyVersion *int
		sha        string
	)
	if err := v.pool.QueryRow(ctx, `
		SELECT tenant_id, storage_url, encryption_key_version, sha256
		  FROM finding_evidence WHERE id=$1`, evidenceID).
		Scan(&tenantID, &storageURL, &keyVersion, &sha); err != nil {
		return nil, err
	}
	tid, oid, ok := parseObjectURL(storageURL)
	if !ok || tid != tenantID {
		return nil, errors.New("evidence: bad storage url")
	}
	raw, err := v.storage.Get(ctx, tid, oid)
	if err != nil {
		return nil, fmt.Errorf("evidence: storage.Get: %w", err)
	}
	if len(raw) < 12 {
		return nil, errors.New("evidence: ciphertext too short")
	}
	var plain []byte
	if keyVersion != nil {
		dek, err := v.tenantKeyByVersion(ctx, tenantID, *keyVersion)
		if err != nil {
			return nil, fmt.Errorf("evidence: load DEK v%d: %w", *keyVersion, err)
		}
		plain, err = decryptWithDEK(dek, raw[12:], raw[:12])
		if err != nil {
			return nil, fmt.Errorf("evidence: decrypt with tenant DEK: %w", err)
		}
	} else {
		plain, err = v.decrypt(raw[12:], raw[:12])
		if err != nil {
			return nil, err
		}
	}
	_ = v.recordCustody(ctx, evidenceID, "accessed", actor, "user", ip, ua, nil)
	return plain, nil
}

// ---------------- Integrity + WORM ------------------------------------------

// VerifyIntegrity re-reads the at-rest blob, decrypts it, recomputes
// sha256, compares to the row's recorded sha256. Records exactly one
// custody event (integrity_verified or integrity_failed).
func (v *Vault) VerifyIntegrity(ctx context.Context, evidenceID uuid.UUID) (bool, error) {
	var (
		tenantID   uuid.UUID
		storageURL string
		keyVersion *int
		sha        string
	)
	if err := v.pool.QueryRow(ctx, `
		SELECT tenant_id, storage_url, encryption_key_version, sha256
		  FROM finding_evidence WHERE id=$1`, evidenceID).
		Scan(&tenantID, &storageURL, &keyVersion, &sha); err != nil {
		return false, err
	}
	tid, oid, ok := parseObjectURL(storageURL)
	if !ok || tid != tenantID {
		return false, errors.New("evidence: bad storage url")
	}
	raw, err := v.storage.Get(ctx, tid, oid)
	if err != nil {
		_ = v.recordCustody(ctx, evidenceID, "integrity_failed", nil, "system", nil, "",
			map[string]any{"error": err.Error()})
		return false, err
	}
	if len(raw) < 12 {
		return false, errors.New("evidence: ciphertext too short")
	}
	var plain []byte
	if keyVersion != nil {
		dek, err := v.tenantKeyByVersion(ctx, tenantID, *keyVersion)
		if err != nil {
			return false, err
		}
		plain, err = decryptWithDEK(dek, raw[12:], raw[:12])
		if err != nil {
			return false, err
		}
	} else {
		plain, err = v.decrypt(raw[12:], raw[:12])
		if err != nil {
			return false, err
		}
	}
	digest := sha256.Sum256(plain)
	got := hex.EncodeToString(digest[:])
	matched := got == sha
	ev := "integrity_verified"
	if !matched {
		ev = "integrity_failed"
	}
	_ = v.recordCustody(ctx, evidenceID, ev, nil, "system", nil, "", map[string]any{
		"expected": sha, "observed": got,
	})
	return matched, nil
}

// EnableWORM locks an evidence object: SweepExpired skips it, delete
// attempts are recorded with custody event "purge_denied".
func (v *Vault) EnableWORM(ctx context.Context, evidenceID uuid.UUID, until time.Time, actor *uuid.UUID) error {
	_, err := v.pool.Exec(ctx, `
		UPDATE finding_evidence
		   SET worm = true,
		       immutable_until = GREATEST(COALESCE(immutable_until, $2), $2)
		 WHERE id=$1`, evidenceID, until)
	if err != nil {
		return err
	}
	return v.recordCustody(ctx, evidenceID, "worm_locked", actor, "user", nil, "",
		map[string]any{"immutable_until": until})
}

// PurgeWithWORMCheck is the production delete path. WORM-locked objects
// stay; the attempt is audited.
func (v *Vault) PurgeWithWORMCheck(ctx context.Context, evidenceID uuid.UUID, actor *uuid.UUID, reason string) (bool, error) {
	var worm bool
	var url string
	if err := v.pool.QueryRow(ctx,
		`SELECT worm, storage_url FROM finding_evidence WHERE id=$1`,
		evidenceID).Scan(&worm, &url); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, errors.New("evidence: not found")
		}
		return false, err
	}
	if worm {
		_ = v.recordCustody(ctx, evidenceID, "purge_denied", actor, "user", nil, "",
			map[string]any{"reason": reason, "blocked_by": "worm"})
		return false, nil
	}
	if tid, oid, ok := parseObjectURL(url); ok {
		_ = v.storage.Delete(ctx, tid, oid)
	}
	if _, err := v.pool.Exec(ctx,
		`UPDATE finding_evidence SET purged_at=now() WHERE id=$1`, evidenceID); err != nil {
		return false, err
	}
	_ = v.recordCustody(ctx, evidenceID, "purged", actor, "user", nil, "",
		map[string]any{"reason": reason})
	return true, nil
}

// ---------------- Chain of custody ------------------------------------------

type CustodyEvent struct {
	ID         uuid.UUID  `json:"id"`
	Event      string     `json:"event"`
	ActorID    *uuid.UUID `json:"actor_id,omitempty"`
	ActorType  string     `json:"actor_type"`
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`
}

func (v *Vault) recordCustody(ctx context.Context, evidenceID uuid.UUID, event string,
	actor *uuid.UUID, actorType string, ip net.IP, ua string, details map[string]any) error {
	if actorType == "" {
		actorType = "user"
	}
	det, _ := json.Marshal(details)
	if det == nil || string(det) == "null" {
		det = []byte("{}")
	}
	_, err := v.pool.Exec(ctx, `
		INSERT INTO evidence_chain_of_custody(evidence_id, event, actor_id,
		    actor_type, ip, user_agent, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
		evidenceID, event, actor, actorType, ipOrNull(ip), nullIfEmpty(ua), det)
	return err
}

func (v *Vault) ChainOfCustody(ctx context.Context, evidenceID uuid.UUID) ([]CustodyEvent, error) {
	rows, err := v.pool.Query(ctx, `
		SELECT id, event, actor_id, actor_type, ip::text, COALESCE(user_agent,''),
		       details, occurred_at
		  FROM evidence_chain_of_custody
		 WHERE evidence_id=$1
		 ORDER BY occurred_at`, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustodyEvent
	for rows.Next() {
		var e CustodyEvent
		var ip *string
		var det []byte
		if err := rows.Scan(&e.ID, &e.Event, &e.ActorID, &e.ActorType,
			&ip, &e.UserAgent, &det, &e.OccurredAt); err != nil {
			return nil, err
		}
		if ip != nil {
			e.IP = *ip
		}
		_ = json.Unmarshal(det, &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ChainOfCustodyMarkdown renders a forensic-grade summary suitable for
// the legal export bundle. Markdown so a downstream PDF pipeline can
// pick it up; format mirrors NIST SP 800-101 evidence handling.
func (v *Vault) ChainOfCustodyMarkdown(ctx context.Context, evidenceID uuid.UUID) (string, error) {
	events, err := v.ChainOfCustody(ctx, evidenceID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Chain of Custody — Evidence `%s`\n\n", evidenceID)
	fmt.Fprintf(&b, "| When | Event | Actor | IP | Detail |\n")
	fmt.Fprintf(&b, "|------|-------|-------|----|--------|\n")
	for _, e := range events {
		actor := e.ActorType
		if e.ActorID != nil {
			actor = fmt.Sprintf("%s/%s", e.ActorType, e.ActorID)
		}
		det := ""
		if len(e.Details) > 0 {
			b2, _ := json.Marshal(e.Details)
			det = string(b2)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			e.OccurredAt.UTC().Format(time.RFC3339), e.Event, actor, e.IP, det)
	}
	return b.String(), nil
}

// VerifyRandomSample picks `n` evidence rows at random (Postgres
// TABLESAMPLE BERNOULLI for cheap sampling) and runs VerifyIntegrity
// on each. Returns (passed, checked, error).
//
// Used by the cron-runner's hourly evidence_integrity_sample task
// to catch bit-rot, half-restored backups, and KEK/DEK rotation
// bugs that would otherwise only surface when a customer requests
// a chain-of-custody report.
//
// Cheap by design: TABLESAMPLE is per-page sampling so even a 10M-
// row table reads ~1% of pages to draw a 100-row sample.
func (v *Vault) VerifyRandomSample(ctx context.Context, n int) (passed, checked int, err error) {
	if n <= 0 {
		return 0, 0, nil
	}
	// TABLESAMPLE BERNOULLI(p) draws roughly p% of rows. For a small
	// requested n we don't need much; cap at 5% for tables of any
	// realistic size.
	rows, err := v.pool.Query(ctx, `
		SELECT id FROM finding_evidence
		 TABLESAMPLE BERNOULLI(5)
		 WHERE encrypted = true
		 LIMIT $1`, n)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		ok, err := v.VerifyIntegrity(ctx, id)
		checked++
		if err != nil {
			// Treat read errors as failures; the caller's metric
			// records (checked - passed) which surfaces it.
			continue
		}
		if ok {
			passed++
		}
	}
	return passed, checked, nil
}
