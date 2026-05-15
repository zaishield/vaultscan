// storage.go — pluggable storage backend for the evidence vault.
//
// The vault encrypts plaintext with AES-256-GCM and hands a single
// blob (nonce || ciphertext) to a Storage implementation. Three
// production-safe backends ship in-tree:
//
//   FilesystemStorage   — local disk, dev/single-node only
//   S3Storage           — any S3-compatible bucket via SigV4
//                         (AWS S3, MinIO, Ceph RGW, Backblaze B2, R2)
//
// The Storage interface is intentionally narrow: a tenant_id-scoped
// (TenantID, ObjectID) tuple maps to opaque bytes. Versioning,
// lifecycle, and replication are the storage backend's responsibility.
package evidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Storage is the contract a backend implements. All methods take a
// context so the backend can honor request-scoped timeouts /
// cancellation.
type Storage interface {
	// Put writes blob at tenantID/objectID. Implementations MUST be
	// idempotent: a re-write of the same (tenant, object) is allowed.
	Put(ctx context.Context, tenantID, objectID uuid.UUID, blob []byte) error
	// Get returns the blob, or an error wrapping ErrObjectNotFound.
	Get(ctx context.Context, tenantID, objectID uuid.UUID) ([]byte, error)
	// Delete removes the blob. Missing objects are not an error.
	Delete(ctx context.Context, tenantID, objectID uuid.UUID) error
	// Name returns a short backend identifier surfaced in metrics +
	// error messages ("filesystem", "s3", "minio", ...).
	Name() string
}

// ErrObjectNotFound is the sentinel that backends wrap when a Get
// hits an absent key. Callers that want to surface a 404 should use
// errors.Is(err, ErrObjectNotFound).
var ErrObjectNotFound = errors.New("evidence: object not found")

// objectURL returns the canonical "vaultscan://<tenant>/<object>"
// reference stored in the DB. Used by both Storage backends.
func objectURL(tenantID, objectID uuid.UUID) string {
	return fmt.Sprintf("vaultscan://%s/%s", tenantID, objectID)
}
