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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zaishield/vaultscan/backend/internal/observability"
)

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
		VALUES ($1, 1, $2, 'platform-master-v1')
		RETURNING key_version`,
		tenantID, wrapped).Scan(&version); err != nil {
		return 0, nil, err
	}
	return version, dek, nil
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
			// block the sweep — next tick retries.
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
		SELECT $1, COALESCE(max(key_version),0)+1, $2, 'platform-master-v1'
		  FROM tenant_data_keys WHERE tenant_id=$1
		RETURNING key_version`, tenantID, wrapped).Scan(&version)
	return version, err
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
	block, err := aes.NewCipher(v.masterKey)
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
