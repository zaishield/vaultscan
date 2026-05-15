// Package secrets is the platform's abstraction over OpenBao / Infisical /
// env-var-backed secret retrieval (Blueprint §30). The env backend is
// developer-grade; production wires the Vault backend via SecretsBackend
// configuration.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Backend is the pluggable contract every secrets provider satisfies.
type Backend interface {
	Get(ctx context.Context, ref string) (string, error)
	Put(ctx context.Context, ref, value string) error
}

type Service struct {
	backend Backend
}

func New(backend Backend) *Service { return &Service{backend: backend} }

// Get returns the secret stored at the canonical reference path. Refs use
// `/`-separated namespaces — e.g. `integrations/jira/api-token` — so the
// production Vault mount path or Infisical project layout can be reused.
func (s *Service) Get(ctx context.Context, ref string) (string, error) {
	if s == nil || s.backend == nil {
		return "", errors.New("secrets: not configured")
	}
	if ref == "" {
		return "", errors.New("secrets: empty ref")
	}
	return s.backend.Get(ctx, ref)
}

func (s *Service) Put(ctx context.Context, ref, value string) error {
	if s == nil || s.backend == nil {
		return errors.New("secrets: not configured")
	}
	return s.backend.Put(ctx, ref, value)
}

// EnvBackend reads/writes secrets from process environment variables.
// `secret/integrations/jira/foo` → env `VAULTSCAN_SECRET_INTEGRATIONS_JIRA_FOO`.
// Intended for local development and CI; production must wire a Vault backend.
type EnvBackend struct{}

func (EnvBackend) envKey(ref string) string {
	cleaned := strings.NewReplacer("/", "_", "-", "_", ".", "_").Replace(ref)
	return "VAULTSCAN_SECRET_" + strings.ToUpper(strings.TrimPrefix(cleaned, "secret_"))
}

func (e EnvBackend) Get(_ context.Context, ref string) (string, error) {
	v := os.Getenv(e.envKey(ref))
	if v == "" {
		return "", fmt.Errorf("secrets: env %q not set", e.envKey(ref))
	}
	return v, nil
}

func (e EnvBackend) Put(_ context.Context, ref, value string) error {
	return os.Setenv(e.envKey(ref), value)
}

// MemoryBackend is a goroutine-safe in-memory provider used by tests.
type MemoryBackend struct {
	store map[string]string
}

func NewMemoryBackend() *MemoryBackend { return &MemoryBackend{store: map[string]string{}} }

func (m *MemoryBackend) Get(_ context.Context, ref string) (string, error) {
	v, ok := m.store[ref]
	if !ok {
		return "", fmt.Errorf("secrets: ref %q not found", ref)
	}
	return v, nil
}

func (m *MemoryBackend) Put(_ context.Context, ref, value string) error {
	m.store[ref] = value
	return nil
}
