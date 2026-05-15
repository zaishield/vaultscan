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
)

type Vault struct {
	pool       *pgxpool.Pool
	audit      *audit.Service
	bus        *eventbus.Bus
	storage    Storage
	rootDir    string  // legacy: used only when no explicit Storage is set
	masterKey  []byte
	urlTTL     time.Duration
}

type Option func(*Vault)

// WithFilesystem mints a FilesystemStorage rooted at dir. Equivalent
// to WithStorage(NewFilesystemStorage(dir)).
func WithFilesystem(dir string) Option        { return func(v *Vault) { v.rootDir = dir } }

// WithStorage attaches a custom Storage backend (S3, MinIO, in-memory
// for tests, etc). Takes precedence over WithFilesystem.
func WithStorage(s Storage) Option            { return func(v *Vault) { v.storage = s } }

func WithURLTTL(ttl time.Duration) Option     { return func(v *Vault) { v.urlTTL = ttl } }

func NewVault(pool *pgxpool.Pool, a *audit.Service, b *eventbus.Bus, masterKeyB64 string, opts ...Option) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("evidence: master key must decode to >=32 bytes")
	}
	v := &Vault{
		pool: pool, audit: a, bus: b,
		masterKey: key[:32],
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

// Record creates a finding_evidence row for an existing object.
func (v *Vault) Record(ctx context.Context, in PutInput) (*models.Evidence, error) {
	storageURL, err := v.Put(ctx, in)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(in.Body)
	hashHex := hex.EncodeToString(digest[:])
	id := uuid.New()
	now := time.Now().UTC()

	_, err = v.pool.Exec(ctx, `
		INSERT INTO finding_evidence(id, tenant_id, partner_id, finding_id, engagement_id,
		    scan_job_id, evidence_type, storage_url, sha256, size_bytes, content_type,
		    encrypted, uploaded_by, uploaded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12,$13)`,
		id, in.TenantID, in.PartnerID, in.FindingID, in.EngagementID, in.ScanJobID,
		in.Kind, storageURL, hashHex, int64(len(in.Body)), in.ContentType, in.UploadedBy, now)
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

// Read returns plaintext bytes for a recorded evidence row.
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
	raw, err := v.storage.Get(ctx, tenantID, objectID)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: storage.Get: %w", err)
	}
	if len(raw) < 12 {
		return nil, nil, errors.New("evidence: ciphertext too short")
	}
	plain, err := v.decrypt(raw[12:], raw[:12])
	if err != nil {
		return nil, nil, err
	}
	_ = v.logAccess(ctx, evidenceID, actor, ip, ua, "download")
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
	exp := time.Now().UTC().Add(v.urlTTL)
	mac := signRef(v.masterKey, evidenceID.String(), exp.Unix())
	return &SignedURL{
		URL:       fmt.Sprintf("%s/api/v1/evidence/%s/download?exp=%d&sig=%s", baseURL, evidenceID, exp.Unix(), mac),
		ExpiresAt: exp,
	}, nil
}

func (v *Vault) VerifySignature(evidenceID uuid.UUID, expUnix int64, sig string) bool {
	if time.Unix(expUnix, 0).Before(time.Now()) {
		return false
	}
	expected := signRef(v.masterKey, evidenceID.String(), expUnix)
	return constantTimeEqualString(expected, sig)
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
	return gcm.Seal(nil, nonce, plain, nil), nonce, nil
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
