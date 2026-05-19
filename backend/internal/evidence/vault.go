// Package evidence implements the encrypted, tenant-isolated evidence vault
// (Blueprint §18). Storage is a pluggable backend; the in-process default
// writes encrypted blobs to a local directory, suitable for development and
// kept identical in shape to the production S3/Ceph adapter.
package evidence

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/models"
	"github.com/zaishield/vaultscan/backend/internal/observability"
)

type Vault struct {
	pool      *pgxpool.Pool
	audit     *audit.Service
	bus       *eventbus.Bus
	storage   Storage
	rootDir   string // legacy: used only when no explicit Storage is set
	masterKey []byte // active KEK (wrap + first-tried unwrap)
	activeKEKID string
	// previousMasterKeys are decommissioned-but-still-needed KEK
	// material. unwrap tries them in order after the active key
	// fails. Operators populate during a rotation window: once
	// RewrapTenantDEKsToActiveKEK has rewrapped every row under the
	// new active KEK, the previous entries can be dropped from
	// config and the old key material destroyed.
	previousMasterKeys [][]byte
	urlTTL             time.Duration
	residency          ResidencyChecker
	podRegion          string
}

// ResidencyChecker is the slice of tenants.Service the vault needs
// for residency enforcement on Record/RecordWithDEK.
type ResidencyChecker interface {
	CheckResidency(ctx context.Context, tenantID uuid.UUID, podRegion string) error
}

// WithResidency wires the data-residency gate. Record paths refuse
// to seal evidence for a tenant pinned to a region different from
// the pod's VAULTSCAN_REGION. Empty podRegion disables.
func WithResidency(r ResidencyChecker, podRegion string) Option {
	return func(v *Vault) {
		v.residency = r
		v.podRegion = podRegion
	}
}

type Option func(*Vault)

// WithFilesystem mints a FilesystemStorage rooted at dir. Equivalent
// to WithStorage(NewFilesystemStorage(dir)).
func WithFilesystem(dir string) Option        { return func(v *Vault) { v.rootDir = dir } }

// WithStorage attaches a custom Storage backend (S3, MinIO, in-memory
// for tests, etc). Takes precedence over WithFilesystem.
func WithStorage(s Storage) Option            { return func(v *Vault) { v.storage = s } }

// Storage returns the configured backend. Exported so test
// scaffolding can construct a sibling Vault that shares the same
// filesystem / S3 location (e.g. simulating a KEK rotation where
// the old + new vault both point at the existing object set).
// Production code does NOT call this — it uses the Vault directly.
func (v *Vault) Storage() Storage { return v.storage }

func WithURLTTL(ttl time.Duration) Option     { return func(v *Vault) { v.urlTTL = ttl } }

// WithActiveKEKID stamps each newly-wrapped DEK row's kek_id column
// with this identifier. Operators use it to track which generation
// of KEK material wrapped each row, which is the index
// RewrapTenantDEKsToActiveKEK uses to find rows that still hold the
// old wrap.
func WithActiveKEKID(id string) Option {
	return func(v *Vault) { v.activeKEKID = id }
}

// WithPreviousMasterKeys registers retired KEK material that the
// vault should fall back to during unwrap when the active key
// can't decrypt a blob. Caller supplies base64-encoded keys, same
// shape as masterKeyB64.
//
// Validation happens at Option construction time via
// ValidatePreviousMasterKeys — boot fails loudly if any key is
// malformed instead of silently filling the slice with nils (the
// prior behaviour, which made unwrap quietly skip retired-key
// branches and surface as "blob can't be decrypted" much later).
// Callers that have already validated their keys can use the option
// directly; everyone else should call the boot-side validator first.
func WithPreviousMasterKeys(keysB64 []string) Option {
	return func(v *Vault) {
		for _, k := range keysB64 {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(b) < 32 {
				// Skip malformed entries rather than appending a nil
				// sentinel. The boot path is expected to have called
				// ValidatePreviousMasterKeys already and surfaced
				// errors; if it didn't, the practical effect of
				// skipping is: retired blobs that needed THIS key
				// won't unwrap (loud failure on next read) — strictly
				// better than the prior silent-nil behaviour where a
				// later loop ranged over nils.
				continue
			}
			v.previousMasterKeys = append(v.previousMasterKeys, b[:32])
		}
	}
}

// ValidatePreviousMasterKeys returns a non-nil error iff any of
// keysB64 fails to decode to ≥32 bytes. Use at boot to fail loud
// before the vault is constructed.
func ValidatePreviousMasterKeys(keysB64 []string) error {
	for i, k := range keysB64 {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return fmt.Errorf("evidence: previous KEK #%d: base64 decode: %w", i, err)
		}
		if len(b) < 32 {
			return fmt.Errorf("evidence: previous KEK #%d: must decode to >=32 bytes (got %d)", i, len(b))
		}
	}
	return nil
}

// knownDevMasterKeys are master-key values that ship in source for
// local development, test harnesses, and example overlays. None of
// them MUST EVER reach a production deployment. NewVault refuses to
// boot when it sees one of these, unless the operator explicitly
// sets VAULTSCAN_ALLOW_DEV_KEYS=true (dev/test path).
//
// To add a new known-bad value: paste its base64 form into the slice
// and a comment naming where it came from.
var knownDevMasterKeys = []string{
	// backend/test/integration/main_test.go harness
	"ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA=",
	// backend/cmd/api/example_config.yaml (any future placeholder)
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
}

// ErrDevKeyInProduction is returned by NewVault when the supplied
// master key matches a known dev/test placeholder and the
// VAULTSCAN_ALLOW_DEV_KEYS escape hatch is not set. Operators see
// this on container boot and fix their config before the API
// accepts a single request.
var ErrDevKeyInProduction = errors.New(
	"evidence: refusing to boot with a known development master key; " +
		"set VAULTSCAN_ALLOW_DEV_KEYS=true ONLY for non-production deployments")

func NewVault(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus, masterKeyB64 string, opts ...Option) (*Vault, error) {
	for _, bad := range knownDevMasterKeys {
		if masterKeyB64 == bad && os.Getenv("VAULTSCAN_ALLOW_DEV_KEYS") != "true" {
			return nil, ErrDevKeyInProduction
		}
	}
	key, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return nil, fmt.Errorf("evidence: master key not valid base64: %w", err)
	}
	// EXACT 32 bytes required. The previous "len(key) < 32" + key[:32]
	// silently truncated a longer key (e.g. an operator who base64'd
	// 33 bytes encrypted everything under only the first 32 — silent
	// mis-key). Refuse out of caution rather than guess intent.
	if len(key) != 32 {
		return nil, fmt.Errorf("evidence: master key must decode to EXACTLY 32 bytes (got %d)", len(key))
	}
	v := &Vault{
		pool: pool, audit: a, bus: b,
		masterKey: key,
		rootDir:   filepath.Join(os.TempDir(), "vaultscan-evidence"),
		urlTTL:    5 * time.Minute,
	}
	for _, o := range opts {
		o(v)
	}
	if v.storage == nil {
		fs, err := NewFilesystemStorage(v.rootDir)
		if err != nil {
			return nil, err
		}
		v.storage = fs
	}
	return v, nil
}

type PutInput struct {
	TenantID     uuid.UUID
	PartnerID    uuid.UUID
	FindingID    *uuid.UUID
	EngagementID *uuid.UUID
	ScanJobID    *uuid.UUID
	Kind         string  // raw_output | screenshot | http_request | ...
	ContentType  string
	Body         []byte
	UploadedBy   *uuid.UUID
}

// Put encrypts the body and stores it via the configured Storage
// backend. The returned URL is an internal reference (vaultscan://...)
// suitable for storage in the DB; a signed download URL is generated
// on read.
func (v *Vault) Put(ctx context.Context, in PutInput) (storageURL string, err error) {
	if in.TenantID == uuid.Nil {
		return "", errors.New("evidence: tenant_id required")
	}
	ciphertext, nonce, err := v.encrypt(in.Body)
	if err != nil {
		return "", err
	}
	id := uuid.New()
	if err := v.storage.Put(ctx, in.TenantID, id, append(nonce, ciphertext...)); err != nil {
		return "", fmt.Errorf("evidence: storage.Put: %w", err)
	}
	return objectURL(in.TenantID, id), nil
}

// putPreferDEK tries the per-tenant DEK path first; if EnsureTenantKey
// fails (e.g. tenant_data_keys schema not present yet, or KMS unreachable
// for the wrap step) it falls back to the master-key Put so the upload
// still completes. Read dispatches on the stored key_version, so the
// fallback objects are decryptable by the same Read path as legacy ones.
func (v *Vault) putPreferDEK(ctx context.Context, in PutInput) (string, *int, error) {
	if in.TenantID == uuid.Nil {
		return "", nil, errors.New("evidence: tenant_id required")
	}
	url, version, dekErr := v.PutWithDEK(ctx, in.TenantID, in.Body)
	if dekErr == nil {
		v := version
		return url, &v, nil
	}
	// Fall back so a transient KMS or migration issue doesn't drop
	// evidence on the floor. Operators see the legacy-key row via
	// encryption_key_version IS NULL counts in the metrics dashboard.
	legacyURL, err := v.Put(ctx, in)
	if err != nil {
		return "", nil, err
	}
	return legacyURL, nil, nil
}

// Record creates a finding_evidence row for an existing object.
//
// Encrypts with the tenant's per-tenant DEK (wrapped under the master
// KEK). Falls back to the master-key path ONLY if EnsureTenantKey fails
// — typically when tenant_data_keys hasn't been migrated yet or the
// caller is the agent-gateway running before tenant provisioning has
// landed. The fallback preserves availability; new tenants always end
// up on the DEK path because EnsureTenantKey self-provisions.
//
// Previously Record always used the master key, so a KEK compromise
// would reveal every tenant's evidence at once. With per-tenant DEK,
// each tenant's wrapped DEK is the unit of compromise.
func (v *Vault) Record(ctx context.Context, in PutInput) (*models.Evidence, error) {
	digest := sha256.Sum256(in.Body)
	hashHex := hex.EncodeToString(digest[:])
	id := uuid.New()
	now := time.Now().UTC()

	storageURL, keyVersion, err := v.putPreferDEK(ctx, in)
	if err != nil {
		return nil, err
	}

	if keyVersion != nil {
		_, err = v.pool.Exec(ctx, `
			INSERT INTO finding_evidence(id, tenant_id, partner_id, finding_id, engagement_id,
			    scan_job_id, evidence_type, storage_url, sha256, size_bytes, content_type,
			    encrypted, encryption_key_version, uploaded_by, uploaded_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12,$13,$14)`,
			id, in.TenantID, in.PartnerID, in.FindingID, in.EngagementID, in.ScanJobID,
			in.Kind, storageURL, hashHex, int64(len(in.Body)), in.ContentType,
			*keyVersion, in.UploadedBy, now)
	} else {
		_, err = v.pool.Exec(ctx, `
			INSERT INTO finding_evidence(id, tenant_id, partner_id, finding_id, engagement_id,
			    scan_job_id, evidence_type, storage_url, sha256, size_bytes, content_type,
			    encrypted, uploaded_by, uploaded_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12,$13)`,
			id, in.TenantID, in.PartnerID, in.FindingID, in.EngagementID, in.ScanJobID,
			in.Kind, storageURL, hashHex, int64(len(in.Body)), in.ContentType,
			in.UploadedBy, now)
	}
	if err != nil {
		return nil, fmt.Errorf("evidence: insert: %w", err)
	}
	_ = v.audit.Record(ctx, audit.Entry{
		PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		PartnerID:  &in.PartnerID, TenantID: &in.TenantID, ActorID: in.UploadedBy,
		Event: audit.EventEvidenceUploaded,
		TargetType: "evidence", TargetID: id.String(),
		Payload: map[string]any{"sha256": hashHex, "size": len(in.Body), "kind": in.Kind},
	})
	return &models.Evidence{
		ID: id, TenantID: in.TenantID, PartnerID: in.PartnerID,
		FindingID: in.FindingID, EngagementID: in.EngagementID, ScanJobID: in.ScanJobID,
		EvidenceType: in.Kind, StorageURL: storageURL, SHA256: hashHex,
		SizeBytes: int64(len(in.Body)), ContentType: in.ContentType,
		Encrypted: true, UploadedAt: now,
	}, nil
}

// Read returns plaintext bytes for a recorded evidence row. Dispatches
// on encryption_key_version: NOT NULL → unwrap the per-tenant DEK and
// decrypt with it; NULL → legacy master-key decrypt (pre-VS-08 rows
// and the rare fallback path inside Record).
func (v *Vault) Read(ctx context.Context, evidenceID uuid.UUID, actor *uuid.UUID, ip net.IP, ua string) ([]byte, *models.Evidence, error) {
	ev, err := v.GetMeta(ctx, evidenceID)
	if err != nil {
		return nil, nil, err
	}
	tenantID, objectID, ok := parseObjectURL(ev.StorageURL)
	if !ok {
		return nil, nil, errors.New("evidence: bad storage url")
	}
	if tenantID != ev.TenantID {
		return nil, nil, errors.New("evidence: tenant id mismatch in storage url")
	}
	// Look up the key version separately rather than expanding GetMeta's
	// scan list — fewer downstream changes for a tiny extra query.
	var keyVersion *int
	if err := v.pool.QueryRow(ctx,
		`SELECT encryption_key_version FROM finding_evidence WHERE id=$1`,
		evidenceID).Scan(&keyVersion); err != nil {
		return nil, nil, fmt.Errorf("evidence: load key_version: %w", err)
	}
	raw, err := v.storage.Get(ctx, tenantID, objectID)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: storage.Get: %w", err)
	}
	if len(raw) < 12 {
		return nil, nil, errors.New("evidence: ciphertext too short")
	}
	var plain []byte
	if keyVersion != nil {
		dek, derr := v.tenantKeyByVersion(ctx, tenantID, *keyVersion)
		if derr != nil {
			return nil, nil, fmt.Errorf("evidence: load DEK v%d: %w", *keyVersion, derr)
		}
		plain, err = decryptWithDEK(dek, raw[12:], raw[:12])
		zeroBytes(dek)
		if err != nil {
			return nil, nil, fmt.Errorf("evidence: decrypt with tenant DEK: %w", err)
		}
	} else {
		plain, err = v.decrypt(raw[12:], raw[:12])
		if err != nil {
			return nil, nil, err
		}
	}
	if err := v.logAccess(ctx, evidenceID, actor, ip, ua, "download"); err != nil {
		// logAccess failure must not leave the download itself a no-op,
		// but the chain-of-custody table missing a row is auditor-visible
		// (the evidence appears to have never been read). Log loud so
		// the on-call sees this; cron-runner integrity sweep flags
		// finding_evidence_custody rows whose count drifts from
		// audit_logs row counts for the same evidence.
		evidenceLogger.Error().
			Err(err).
			Str("op", "logAccess").
			Str("evidence_id", evidenceID.String()).
			Msg("custody row write failed; chain-of-custody table will under-count this evidence's reads")
	}
	_ = v.audit.Record(ctx, audit.Entry{
		PlatformID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"),
		PartnerID:  &ev.PartnerID, TenantID: &ev.TenantID, ActorID: actor,
		Event: audit.EventEvidenceDownloaded,
		TargetType: "evidence", TargetID: evidenceID.String(),
		IP: ip, UserAgent: ua,
	})
	_ = v.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.EvidenceDownloaded, TenantID: &ev.TenantID, PartnerID: &ev.PartnerID,
		ActorID: actor, Payload: map[string]any{"evidence_id": evidenceID},
	})
	return plain, ev, nil
}

func (v *Vault) GetMeta(ctx context.Context, evidenceID uuid.UUID) (*models.Evidence, error) {
	e := &models.Evidence{}
	err := v.pool.QueryRow(ctx, `
		SELECT id, tenant_id, partner_id, finding_id, engagement_id, scan_job_id,
		       evidence_type, storage_url, sha256, size_bytes, content_type,
		       encrypted, immutable_until, expires_at, uploaded_at
		  FROM finding_evidence WHERE id=$1`, evidenceID).
		Scan(&e.ID, &e.TenantID, &e.PartnerID, &e.FindingID, &e.EngagementID, &e.ScanJobID,
			&e.EvidenceType, &e.StorageURL, &e.SHA256, &e.SizeBytes, &e.ContentType,
			&e.Encrypted, &e.ImmutableUntil, &e.ExpiresAt, &e.UploadedAt)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// SweepExpired purges evidence whose retention window has passed but whose
// immutable-until window has elapsed (or was never set). Blueprint §18.2
// mandates "immutable retention option" — we honour both the soft expiry
// (expires_at) and the hard immutability lock (immutable_until). Returns
// the number of objects deleted.
//
// Intended to run periodically (e.g. once per hour) via a worker.
func (v *Vault) SweepExpired(ctx context.Context) (int, error) {
	rows, err := v.pool.Query(ctx, `
		SELECT id, storage_url FROM finding_evidence
		 WHERE expires_at IS NOT NULL
		   AND expires_at < now()
		   AND purged_at IS NULL
		   AND (immutable_until IS NULL OR immutable_until < now())
		 LIMIT 1000`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type purge struct {
		id  uuid.UUID
		url string
	}
	var pending []purge
	for rows.Next() {
		var p purge
		if err := rows.Scan(&p.id, &p.url); err != nil {
			return 0, err
		}
		pending = append(pending, p)
	}
	purged := 0
	for _, p := range pending {
		if tenantID, objectID, ok := parseObjectURL(p.url); ok {
			if delErr := v.storage.Delete(ctx, tenantID, objectID); delErr != nil {
				// Don't fail the whole sweep on a single delete failure;
				// the row stays unpurged so we'll retry next tick.
				continue
			}
		}
		if _, err := v.pool.Exec(ctx,
			`UPDATE finding_evidence SET purged_at = now() WHERE id=$1`, p.id); err != nil {
			return purged, err
		}
		purged++
	}
	return purged, nil
}

// SignedDownloadURL produces a short-TTL signed reference (Blueprint §18.2).
// In production this becomes an S3/Ceph presigned URL; here we mint a token.
type SignedURL struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (v *Vault) SignedDownloadURL(ctx context.Context, evidenceID uuid.UUID, baseURL string) (*SignedURL, error) {
	// Resolve the tenant id from the row so the signature can bind
	// to it. Without this binding, a signed URL minted for tenant A
	// can be replayed against the same evidence_id under tenant B.
	var tenantID uuid.UUID
	if err := v.pool.QueryRow(ctx,
		`SELECT tenant_id FROM finding_evidence WHERE id = $1`, evidenceID).
		Scan(&tenantID); err != nil {
		return nil, fmt.Errorf("evidence: lookup tenant for signed URL: %w", err)
	}
	exp := time.Now().UTC().Add(v.urlTTL)
	mac := signRef(v.masterKey, tenantID.String(), evidenceID.String(), exp.Unix())
	return &SignedURL{
		URL:       fmt.Sprintf("%s/api/v1/evidence/%s/download?exp=%d&sig=%s", baseURL, evidenceID, exp.Unix(), mac),
		ExpiresAt: exp,
	}, nil
}

// VerifySignature verifies a signed URL's HMAC against the active
// KEK AND each retired KEK. Without the retired-KEK fallback, a
// signed URL minted before a KEK rotation would 403 immediately
// after rotation — a UX cliff that operators kept paying for
// in the original implementation.
//
// Caller MUST pass `tenantID` resolved from the row (NOT the URL),
// since the URL's tenant is part of the signed envelope.
func (v *Vault) VerifySignature(ctx context.Context, evidenceID uuid.UUID, expUnix int64, sig string) bool {
	if time.Unix(expUnix, 0).Before(time.Now()) {
		return false
	}
	// Cap exp at +24h beyond now so a leaked key can't sign a URL
	// that lasts forever. Matches the longest TTL we'd ever set
	// in practice (legal-export bundles).
	if time.Unix(expUnix, 0).After(time.Now().Add(24 * time.Hour)) {
		return false
	}
	var tenantID uuid.UUID
	if err := v.pool.QueryRow(ctx,
		`SELECT tenant_id FROM finding_evidence WHERE id = $1`, evidenceID).
		Scan(&tenantID); err != nil {
		return false
	}
	// Try active KEK first.
	expected := signRef(v.masterKey, tenantID.String(), evidenceID.String(), expUnix)
	if constantTimeEqualString(expected, sig) {
		return true
	}
	// Then each retired KEK (rotation window).
	for _, kek := range v.previousMasterKeys {
		if len(kek) == 0 {
			continue
		}
		if constantTimeEqualString(signRef(kek, tenantID.String(), evidenceID.String(), expUnix), sig) {
			return true
		}
	}
	return false
}

func (v *Vault) logAccess(ctx context.Context, evidenceID uuid.UUID, actor *uuid.UUID, ip net.IP, ua, action string) error {
	_, err := v.pool.Exec(ctx, `
		INSERT INTO evidence_access_logs(evidence_id, user_id, action, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5)`,
		evidenceID, actor, action, ipOrNull(ip), nullIfEmpty(ua))
	return err
}

// AES-256-GCM envelope encryption with random per-object nonce.
func (v *Vault) encrypt(plain []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(v.masterKey)
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
	out := gcm.Seal(nil, nonce, plain, nil)
	observability.AESGCMSeals.WithLabelValues("master-kek-legacy").Inc()
	return out, nonce, nil
}

func (v *Vault) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
