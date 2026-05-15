// Package scanner contains the external scanner worker — the binary that
// pulls dispatched external scan jobs, verifies their signatures + image
// digests, executes the tool, ingests the results into the findings engine,
// and reports status back. In production this runs as a per-region pod that
// owns a scanner Kubernetes namespace (Blueprint §12). The dev build runs
// the binary against the host's Postgres + invokes the tools via the agent's
// in-process runner.
package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/cosign"
)

// Image is one registered scanner image.
type Image struct {
	Tool       string
	Reference  string
	Digest     string
	Plane      string
	Enabled    bool
	// Cosign bundle the registry has cached for this image. Empty when the
	// image hasn't been cosign-signed yet — the verifier treats that as a
	// soft fail (Allow / RequireSignatures decided by config).
	Cosign cosign.Bundle
}

// Registry resolves a tool name to its allow-listed image + digest. The
// scanner worker MUST verify the running image's digest AND its cosign
// signature before executing anything (Blueprint §12.3).
type Registry struct {
	pool   *pgxpool.Pool
	cosign *cosign.Service

	// RequireSignatures, when true, makes VerifyImage refuse any tool that
	// doesn't carry a verified cosign signature. Production: true.
	// Dev / first-boot: false (let unsigned images through with a warning
	// so operators can stand the stack up before pushing signed images).
	RequireSignatures bool
}

// NewRegistry returns a registry wired with a cosign verifier. Pass
// RequireSignatures via the dedicated setter so callers can flip it from
// config at boot.
func NewRegistry(pool *pgxpool.Pool, c *cosign.Service) *Registry {
	return &Registry{pool: pool, cosign: c}
}

// Lookup returns the currently-enabled image for a tool in the requested
// plane (external/internal). Returns the cached cosign bundle alongside —
// the caller passes it to VerifyImage.
func (r *Registry) Lookup(ctx context.Context, tool, plane string) (*Image, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT tool, image_ref, image_digest, plane, enabled,
		       COALESCE(cosign_payload, ''), COALESCE(cosign_signature, ''),
		       COALESCE(cosign_key_id, '')
		  FROM scanner_image_registry
		 WHERE tool = $1
		   AND enabled = true
		   AND (plane = $2 OR plane = 'both')
		 ORDER BY registered_at DESC
		 LIMIT 1`, tool, plane)
	var img Image
	if err := row.Scan(&img.Tool, &img.Reference, &img.Digest, &img.Plane, &img.Enabled,
		&img.Cosign.PayloadB64, &img.Cosign.SignatureB64, &img.Cosign.KeyID); err != nil {
		return nil, fmt.Errorf("%w: tool=%q plane=%q", ErrUnregisteredImage, tool, plane)
	}
	return &img, nil
}

// VerifyDigest is the cheap pre-flight: registry says "image X has digest
// Y", we make sure the runtime is about to execute Y.
func (r *Registry) VerifyDigest(expected *Image, observed string) error {
	if expected == nil {
		return ErrUnregisteredImage
	}
	if observed == "" {
		return nil // dev: runner doesn't expose a digest; production K8s does.
	}
	if expected.Digest != observed {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrDigestMismatch, expected.Digest, observed)
	}
	return nil
}

// VerifyImage is the full gate the scanner worker calls before exec:
//
//   1. Digest matches the allow-list entry.
//   2. The cached cosign bundle (if any) is signed by an active trusted key
//      whose payload covers this image's digest.
//
// Returns the matched key id on success. If RequireSignatures is true and
// no cosign bundle is present, the call fails closed.
func (r *Registry) VerifyImage(ctx context.Context, img *Image, observedDigest, plane string, actor any) (string, error) {
	if err := r.VerifyDigest(img, observedDigest); err != nil {
		return "", err
	}
	if img.Cosign.SignatureB64 == "" || img.Cosign.PayloadB64 == "" {
		if r.RequireSignatures {
			r.logUnsigned(ctx, img)
			return "", fmt.Errorf("%w: image %s has no cosign signature; RequireSignatures=true",
				ErrUnsignedImage, img.Reference)
		}
		// soft-fail in dev — return an empty key id so the worker can log it.
		return "", nil
	}
	res, err := r.cosign.VerifyImage(ctx, img.Reference, img.Digest, img.Cosign, plane)
	if err != nil {
		return "", err
	}
	// Audit every decision — accept or reject. This is the trail the §32
	// auditor needs to defend the platform.
	_ = r.cosign.LogDecision(ctx, img.Reference, res, nil)
	if res.Decision != cosign.DecisionAccepted {
		return "", fmt.Errorf("%w: %s — %s", ErrCosignRejected, res.Decision, res.Reason)
	}
	return res.MatchedKey, nil
}

// logUnsigned records the unsigned-image attempt so an auditor can spot
// drift from policy (someone pushed a tool without re-signing).
func (r *Registry) logUnsigned(ctx context.Context, img *Image) {
	_, _ = r.pool.Exec(ctx, `
		INSERT INTO cosign_verifications(image_ref, image_digest, decision, reason)
		VALUES ($1, $2, 'rejected_unknown_key', 'no cosign signature attached')`,
		img.Reference, img.Digest)
}

// ErrUnregisteredImage indicates the requested tool has no allow-listed image.
var ErrUnregisteredImage = errors.New("scanner: image not registered")

// ErrDigestMismatch indicates the observed image digest doesn't match the
// registered allow-list entry.
var ErrDigestMismatch = errors.New("scanner: image digest mismatch")

// ErrUnsignedImage indicates the registry doesn't have a cosign bundle for
// this image and RequireSignatures is true.
var ErrUnsignedImage = errors.New("scanner: image is not cosign-signed")

// ErrCosignRejected indicates the cosign bundle didn't verify under any
// active trusted key.
var ErrCosignRejected = errors.New("scanner: cosign signature rejected")
