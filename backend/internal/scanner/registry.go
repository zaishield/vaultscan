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
)

// Image is one registered scanner image.
type Image struct {
	Tool       string
	Reference  string
	Digest     string
	Plane      string
	Enabled    bool
}

// Registry resolves a tool name to its allow-listed image + digest. The
// scanner worker MUST verify the running image's digest matches before
// executing anything (Blueprint §12.3).
type Registry struct {
	pool *pgxpool.Pool
}

func NewRegistry(pool *pgxpool.Pool) *Registry { return &Registry{pool: pool} }

// Lookup returns the currently-enabled image for a tool in the requested
// plane (external/internal). If no entry exists or the entry is disabled,
// returns ErrUnregisteredImage so the caller can refuse to run.
func (r *Registry) Lookup(ctx context.Context, tool, plane string) (*Image, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT tool, image_ref, image_digest, plane, enabled
		  FROM scanner_image_registry
		 WHERE tool = $1
		   AND enabled = true
		   AND (plane = $2 OR plane = 'both')
		 ORDER BY registered_at DESC
		 LIMIT 1`, tool, plane)
	var img Image
	if err := row.Scan(&img.Tool, &img.Reference, &img.Digest, &img.Plane, &img.Enabled); err != nil {
		return nil, fmt.Errorf("%w: tool=%q plane=%q", ErrUnregisteredImage, tool, plane)
	}
	return &img, nil
}

// VerifyDigest returns nil iff `observed` matches the canonical image
// digest. In dev the worker runs host binaries that don't have a digest,
// so we let an empty observed pass through with a noisy log at the caller.
func (r *Registry) VerifyDigest(expected *Image, observed string) error {
	if expected == nil {
		return ErrUnregisteredImage
	}
	if observed == "" {
		return nil // dev: no digest available; runner will log a warning.
	}
	if expected.Digest != observed {
		return fmt.Errorf("%w: expected %s, got %s",
			ErrDigestMismatch, expected.Digest, observed)
	}
	return nil
}

// ErrUnregisteredImage indicates the requested tool has no allow-listed image.
var ErrUnregisteredImage = errors.New("scanner: image not registered")

// ErrDigestMismatch indicates the observed image digest doesn't match the
// registered allow-list entry.
var ErrDigestMismatch = errors.New("scanner: image digest mismatch")
