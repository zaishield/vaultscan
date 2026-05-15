// Package config — production_guard validates that no dev-default secrets
// or unsafe configurations remain when VAULTSCAN_ENV=production.
//
// The contract: if Env == "production", Load() must refuse to start the
// process if ANY of the following are still at their dev defaults:
//   - JWT shared secret
//   - Evidence master KEK
//   - Scanner pull KEK
//   - Object store credentials
//   - Database URL (still pointing at localhost / no sslmode)
//   - Agent-gateway cert path (must be supplied, never auto-mint)
//   - Job-signing key
//   - Keycloak issuer (still localhost)
//
// Boot-refusal beats silent insecurity. Ops gets a clear diagnostic; we
// never ship a tenant key wrapped with a 32-byte string ending in
// "change-me".
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// devDefaults catalogs the literal values we ship in Load() so we can
// detect them at boot. Stored as sha256 hashes so the strings themselves
// don't sit in compiled binaries as obvious recovery targets (mild
// defence-in-depth — anyone with the source can compute these, but we
// avoid grepping the binary).
var devDefaults = map[string]string{
	"jwt-shared-secret":     sha256hex("dev-only-shared-secret-change-me"),
	"evidence-master-key":   sha256hex("ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA="),
	"scanner-pull-key":      sha256hex("ZGV2LXNjYW5uZXItcHVsbC1tYXN0ZXIta2V5LTAwMDA="),
	"object-store-secret":   sha256hex("vaultscan-dev-secret"),
	"job-signing-key-id":    sha256hex("dev-key-1"),
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ProductionConfigError is returned when Env=production but the config
// is still carrying dev defaults. Returned as a single error with every
// offending check listed so ops fixes all of them in one pass.
type ProductionConfigError struct {
	Violations []string
}

func (e *ProductionConfigError) Error() string {
	return "VAULTSCAN refuses to start in production mode: " +
		strings.Join(e.Violations, "; ")
}

// validateProduction runs the full set of production-mode gates and
// returns a *ProductionConfigError if any fail. The caller (Load) is
// expected to short-circuit on this error.
//
// Each check is independent — we accumulate violations rather than
// fail-fast so ops gets a complete punch list, not a one-at-a-time
// whack-a-mole.
func (c *Config) validateProduction() error {
	if !c.isProductionMode() {
		return nil
	}
	var v []string

	// --- Secrets that must be operator-provided ---
	if sha256hex(c.JWTSharedSecret) == devDefaults["jwt-shared-secret"] {
		v = append(v, "VAULTSCAN_JWT_SECRET is still the dev default — set to a long, random secret")
	}
	if c.JWTSharedSecret != "" && len(c.JWTSharedSecret) < 32 {
		v = append(v, "VAULTSCAN_JWT_SECRET must be ≥32 bytes")
	}
	if sha256hex(c.EvidenceMasterKey) == devDefaults["evidence-master-key"] {
		v = append(v, "VAULTSCAN_EVIDENCE_MASTER_KEY is still the dev default — generate a fresh 32-byte base64 KEK")
	}
	if err := validateBase64KEK(c.EvidenceMasterKey, 32); err != nil {
		v = append(v, "VAULTSCAN_EVIDENCE_MASTER_KEY invalid: "+err.Error())
	}
	if sha256hex(c.ScannerPullKey) == devDefaults["scanner-pull-key"] {
		v = append(v, "VAULTSCAN_SCANNER_PULL_KEY is still the dev default — generate a fresh 32-byte base64 KEK")
	}
	if err := validateBase64KEK(c.ScannerPullKey, 32); err != nil {
		v = append(v, "VAULTSCAN_SCANNER_PULL_KEY invalid: "+err.Error())
	}
	if sha256hex(c.ObjectStoreSecret) == devDefaults["object-store-secret"] {
		v = append(v, "VAULTSCAN_OBJECT_STORE_SECRET is still the dev default")
	}
	if sha256hex(c.JobSigningKeyID) == devDefaults["job-signing-key-id"] && c.JobSigningKeyPEM == "" {
		v = append(v, "VAULTSCAN_JOB_SIGNING_KEY must be set (and key-id rotated from dev-key-1)")
	}

	// --- Infrastructure URLs that must point at managed services ---
	if isLocalhostURL(c.DatabaseURL) {
		v = append(v, "VAULTSCAN_DATABASE_URL points at localhost")
	}
	if !strings.Contains(c.DatabaseURL, "sslmode=") ||
		strings.Contains(c.DatabaseURL, "sslmode=disable") {
		v = append(v, "VAULTSCAN_DATABASE_URL must enable TLS (sslmode=require/verify-full)")
	}
	if isLocalhostURL(c.OpenSearchURL) {
		v = append(v, "VAULTSCAN_OPENSEARCH_URL points at localhost")
	}
	if isLocalhostURL(c.EventBusURL) {
		v = append(v, "VAULTSCAN_EVENTBUS_URL points at localhost")
	}
	if isLocalhostURL(c.ObjectStoreURL) {
		v = append(v, "VAULTSCAN_OBJECT_STORE_URL points at localhost")
	}
	if isLocalhostURL(c.KeycloakIssuer) {
		v = append(v, "VAULTSCAN_KEYCLOAK_ISSUER points at localhost")
	}
	if isLocalhostURL(c.APIPublicURLValue) {
		v = append(v, "VAULTSCAN_API_PUBLIC_URL points at localhost")
	}

	// --- Agent gateway must have a real cert, never auto-mint ---
	if c.AgentGatewayCertPath == "" || c.AgentGatewayKeyPath == "" {
		v = append(v, "VAULTSCAN_AGENT_GW_CERT and VAULTSCAN_AGENT_GW_KEY must point at a PKI-issued cert in production")
	}

	// --- Secrets backend should not be raw env in prod (use OpenBao / Infisical / KMS) ---
	if c.SecretsBackend == "env" {
		v = append(v, "VAULTSCAN_SECRETS_BACKEND=env is insecure for production — use 'openbao', 'infisical', or 'awskms'")
	}

	// --- CORS must be locked down (no localhost origins, no wildcards) ---
	for _, origin := range c.CORSAllowedOrigins {
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") ||
			origin == "*" {
			v = append(v, "VAULTSCAN_CORS_ALLOWED_ORIGINS contains an unsafe origin: "+origin)
		}
	}

	if len(v) > 0 {
		return &ProductionConfigError{Violations: v}
	}
	return nil
}

// isProductionMode normalizes the env string so "prod", "production",
// "PROD", etc all activate the guard.
func (c *Config) isProductionMode() bool {
	e := strings.ToLower(strings.TrimSpace(c.Env))
	return e == "production" || e == "prod"
}

func isLocalhostURL(u string) bool {
	low := strings.ToLower(u)
	return strings.Contains(low, "localhost") ||
		strings.Contains(low, "127.0.0.1") ||
		strings.Contains(low, "0.0.0.0") ||
		strings.Contains(low, "://api:") ||
		strings.Contains(low, "://db:") ||
		strings.Contains(low, "://postgres:")
}

func validateBase64KEK(s string, wantBytes int) error {
	if s == "" {
		return errors.New("empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != wantBytes {
		return fmt.Errorf("got %d bytes, want %d", len(raw), wantBytes)
	}
	// Reject obviously weak keys: all-zero, all-FF, monotonic.
	if isWeakBytes(raw) {
		return errors.New("low-entropy key (all-zero, all-same-byte, or monotonic)")
	}
	return nil
}

func isWeakBytes(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	first := b[0]
	allSame := true
	monotonic := true
	for i := 1; i < len(b); i++ {
		if b[i] != first {
			allSame = false
		}
		if b[i] != b[i-1]+1 {
			monotonic = false
		}
	}
	return allSame || monotonic
}
