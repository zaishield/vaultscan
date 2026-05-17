// image_digests.go — load the immutable digest pin for each scanner
// image. CI's `scanner-image-sign-and-pin` workflow writes
// tools/scanner-images/digests.json on every release tag; this loader
// surfaces those digests so the orchestrator's job materialiser uses
// `<image>@sha256:<digest>` instead of the mutable `<image>:latest`.
//
// Without digest pinning, an attacker who compromises the registry
// can substitute a malicious image at the `:latest` tag — Kyverno's
// cosign verify policy catches it for the API/portal/etc but pinning
// is still defense-in-depth.
//
// Fallback: if the file is missing (dev cluster, no release tag
// pushed yet) the orchestrator falls back to the legacy `:latest`
// reference and logs a one-time warning.

package scanorch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ImageDigestRegistry is a thread-safe map of tool → digest, loaded
// from JSON at boot or refreshed on a deploy hook.
type ImageDigestRegistry struct {
	mu       sync.RWMutex
	digests  map[string]string
	version  string
	registry string
}

// NewImageDigestRegistry loads from the given JSON file path. Returns
// an empty registry (no error) if the file doesn't exist — callers
// fall back to mutable tags.
func NewImageDigestRegistry(path string) (*ImageDigestRegistry, error) {
	r := &ImageDigestRegistry{digests: map[string]string{}}
	if path == "" {
		return r, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	var doc struct {
		Version  string            `json:"version"`
		Registry string            `json:"registry"`
		Digests  map[string]string `json:"digests"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("scanorch: parse digests.json: %w", err)
	}
	r.digests = doc.Digests
	if r.digests == nil {
		r.digests = map[string]string{}
	}
	r.version = doc.Version
	r.registry = doc.Registry
	return r, nil
}

// ImageRefFor returns the pinned, signed image reference for tool.
// Format:  <registry>/<tool>@sha256:<digest>
// Falls back to  <registry>/<tool>:latest  when the tool isn't in
// the registry yet (newly-added tool, dev cluster, etc).
//
// fallbackRegistry is used when this registry was loaded with an
// empty `registry` field (mostly tests).
func (r *ImageDigestRegistry) ImageRefFor(tool, fallbackRegistry string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	registry := r.registry
	if registry == "" {
		registry = fallbackRegistry
	}
	if d, ok := r.digests[tool]; ok && d != "" {
		return fmt.Sprintf("%s/%s@%s", registry, tool, d)
	}
	// Latest-tag fallback. Emit a one-time warning via the hook
	// (cmd/api binds it to a Prometheus counter + log) so ops know
	// they're shipping unpinned images. A mutable tag is a known
	// supply-chain risk: a compromised registry can substitute
	// malicious images without any audit trail. Production should
	// have every scanner pinned.
	if unpinnedSink != nil {
		unpinnedSink(tool)
	}
	return fmt.Sprintf("%s/%s:latest", registry, tool)
}

// unpinnedSink is called once per tool lookup that falls back to
// :latest. cmd/api binds it to observability.ScannerUnpinnedHits
// without the scanorch package importing observability. Nil = no-op.
var unpinnedSink func(tool string)

// SetUnpinnedSink wires the unpinned-fallback callback.
func SetUnpinnedSink(f func(tool string)) { unpinnedSink = f }

// IsPinned reports whether tool has an explicit digest entry.
// Operators alert on this dropping to false for any tool the
// orchestrator references.
func (r *ImageDigestRegistry) IsPinned(tool string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.digests[tool]
	return ok
}

// Version returns the release tag the digests were captured against
// (e.g. "v1.4.0"). Empty string means no registry was loaded.
func (r *ImageDigestRegistry) Version() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// All returns a copy of the digest map for inspection / metrics.
func (r *ImageDigestRegistry) All() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.digests))
	for k, v := range r.digests {
		out[k] = v
	}
	return out
}

// ErrNoDigest is returned by ImageRefForStrict when the tool has no
// pin AND the registry is configured to refuse unpinned references
// (production with VAULTSCAN_REQUIRE_PINNED_IMAGES=true).
var ErrNoDigest = errors.New("scanorch: image digest pin missing")

// ImageRefForStrict is ImageRefFor that errors instead of falling
// back to :latest. Use this in production code paths that MUST never
// emit a mutable tag.
func (r *ImageDigestRegistry) ImageRefForStrict(tool, fallbackRegistry string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.digests[tool]
	if !ok || d == "" {
		return "", fmt.Errorf("%w: tool=%s", ErrNoDigest, tool)
	}
	registry := r.registry
	if registry == "" {
		registry = fallbackRegistry
	}
	return fmt.Sprintf("%s/%s@%s", registry, tool, d), nil
}
