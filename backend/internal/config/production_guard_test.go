package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestValidateProduction_devEnvIsNoOp(t *testing.T) {
	c := &Config{
		Env:               "development",
		JWTSharedSecret:   "dev-only-shared-secret-change-me",
		EvidenceMasterKey: "ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktMzJieXRlcyE=",
	}
	if err := c.validateProduction(); err != nil {
		t.Fatalf("dev env should not validate: %v", err)
	}
}

func TestValidateProduction_rejectsAllDevDefaults(t *testing.T) {
	c := &Config{
		Env:               "production",
		JWTSharedSecret:   "dev-only-shared-secret-change-me",
		EvidenceMasterKey: "ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktMzJieXRlcyE=",
		ScannerPullKey:    "ZGV2LXNjYW5uZXItcHVsbC1tYXN0ZXIta2V5LTAwMDA=",
		ObjectStoreSecret: "vaultscan-dev-secret",
		DatabaseURL:       "postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable",
		OpenSearchURL:     "http://localhost:9200",
		EventBusURL:       "nats://localhost:4222",
		ObjectStoreURL:    "http://localhost:9000",
		KeycloakIssuer:    "http://localhost:8081/realms/vaultscan",
		APIPublicURLValue: "http://api:8080",
		JobSigningKeyID:   "dev-key-1",
		SecretsBackend:    "env",
		CORSAllowedOrigins: []string{"http://localhost:5173"},
	}
	err := c.validateProduction()
	if err == nil {
		t.Fatal("expected violations")
	}
	var pe *ProductionConfigError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProductionConfigError, got %T", err)
	}
	// Spot-check we caught the high-severity ones (count must be at least
	// the count of critical secrets we shipped with dev defaults).
	want := []string{
		"JWT_SECRET",
		"EVIDENCE_MASTER_KEY",
		"SCANNER_PULL_KEY",
		"OBJECT_STORE_SECRET",
		"DATABASE_URL",
		"OPENSEARCH_URL",
		"EVENTBUS_URL",
		"KEYCLOAK_ISSUER",
		"SECRETS_BACKEND",
		"CORS_ALLOWED_ORIGINS",
		"AGENT_GW_CERT",
		"RATE_LIMIT_BACKEND",
	}
	joined := strings.Join(pe.Violations, "|")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing violation for %s; got: %s", w, joined)
		}
	}
}

func TestValidateProduction_acceptsHardenedConfig(t *testing.T) {
	c := &Config{
		Env:               "production",
		JWTSharedSecret:   "a-very-long-randomly-generated-secret-at-least-32-bytes-1234567890",
		EvidenceMasterKey: base64.StdEncoding.EncodeToString(randomBytes(32)),
		ScannerPullKey:    base64.StdEncoding.EncodeToString(randomBytes(32)),
		ObjectStoreSecret: "real-iam-secret-from-vault",
		DatabaseURL:       "postgres://vs:pw@prod-db.internal:5432/vaultscan?sslmode=verify-full",
		OpenSearchURL:     "https://opensearch.prod.internal:9200",
		EventBusURL:       "nats://nats.prod.internal:4222",
		ObjectStoreURL:    "https://s3.us-east-1.amazonaws.com",
		KeycloakIssuer:    "https://idp.zaishield.com/realms/vaultscan",
		APIPublicURLValue: "https://api.vaultscan.zaishield.com",
		JobSigningKeyID:   "prod-key-2026-q2",
		JobSigningKeyPEM:  "PEM-DATA-HERE",
		AgentGatewayCertPath: "/run/secrets/agent-gw.crt",
		AgentGatewayKeyPath:  "/run/secrets/agent-gw.key",
		SecretsBackend:    "openbao",
		CORSAllowedOrigins: []string{"https://portal.vaultscan.zaishield.com"},
		RateLimitBackend:   "redis",
		RateLimitRedisAddr: "redis.prod.internal:6379",
	}
	if err := c.validateProduction(); err != nil {
		t.Fatalf("hardened config rejected: %v", err)
	}
}

func TestValidateProduction_rejectsShortJWTSecret(t *testing.T) {
	c := newProdConfig()
	c.JWTSharedSecret = "tooshort"
	err := c.validateProduction()
	if err == nil || !strings.Contains(err.Error(), "≥32 bytes") {
		t.Fatalf("expected short-secret rejection, got %v", err)
	}
}

func TestValidateProduction_rejectsWeakKEK(t *testing.T) {
	c := newProdConfig()
	c.EvidenceMasterKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	err := c.validateProduction()
	if err == nil || !strings.Contains(err.Error(), "low-entropy") {
		t.Fatalf("expected low-entropy rejection, got %v", err)
	}
}

func TestValidateProduction_rejectsWrongLengthKEK(t *testing.T) {
	c := newProdConfig()
	c.EvidenceMasterKey = base64.StdEncoding.EncodeToString(randomBytes(16))
	err := c.validateProduction()
	if err == nil || !strings.Contains(err.Error(), "got 16 bytes") {
		t.Fatalf("expected length rejection, got %v", err)
	}
}

func TestValidateProduction_rejectsWildcardCORS(t *testing.T) {
	c := newProdConfig()
	c.CORSAllowedOrigins = []string{"*"}
	err := c.validateProduction()
	if err == nil || !strings.Contains(err.Error(), "*") {
		t.Fatalf("expected wildcard rejection, got %v", err)
	}
}

func TestValidateProduction_rejectsAutoMintCert(t *testing.T) {
	c := newProdConfig()
	c.AgentGatewayCertPath = ""
	c.AgentGatewayKeyPath = ""
	err := c.validateProduction()
	if err == nil || !strings.Contains(err.Error(), "AGENT_GW_CERT") {
		t.Fatalf("expected cert-required rejection, got %v", err)
	}
}

func TestValidateProduction_normalizesEnvCase(t *testing.T) {
	for _, env := range []string{"production", "PRODUCTION", "Production", "prod", "PROD", "  production  "} {
		c := newProdConfig()
		c.Env = env
		c.JWTSharedSecret = "dev-only-shared-secret-change-me"
		err := c.validateProduction()
		if err == nil {
			t.Errorf("env=%q: expected rejection, got none", env)
		}
	}
}

func TestIsWeakBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		weak bool
	}{
		{"all-zero", make([]byte, 32), true},
		{"all-FF", bytesRep(0xff, 32), true},
		{"monotonic", monotonicBytes(32), true},
		{"random", randomBytes(32), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isWeakBytes(c.in); got != c.weak {
				t.Errorf("got %v, want %v", got, c.weak)
			}
		})
	}
}

// --- helpers ---

func newProdConfig() *Config {
	return &Config{
		Env:               "production",
		JWTSharedSecret:   "a-very-long-randomly-generated-secret-at-least-32-bytes-1234567890",
		EvidenceMasterKey: base64.StdEncoding.EncodeToString(randomBytes(32)),
		ScannerPullKey:    base64.StdEncoding.EncodeToString(randomBytes(32)),
		ObjectStoreSecret: "real-secret",
		DatabaseURL:       "postgres://vs:pw@prod-db.internal:5432/vaultscan?sslmode=verify-full",
		OpenSearchURL:     "https://opensearch.prod.internal:9200",
		EventBusURL:       "nats://nats.prod.internal:4222",
		ObjectStoreURL:    "https://s3.us-east-1.amazonaws.com",
		KeycloakIssuer:    "https://idp.zaishield.com/realms/vaultscan",
		APIPublicURLValue: "https://api.vaultscan.zaishield.com",
		JobSigningKeyID:   "prod-key-2026-q2",
		JobSigningKeyPEM:  "PEM",
		AgentGatewayCertPath: "/run/secrets/agent-gw.crt",
		AgentGatewayKeyPath:  "/run/secrets/agent-gw.key",
		SecretsBackend:    "openbao",
		CORSAllowedOrigins: []string{"https://portal.vaultscan.zaishield.com"},
		RateLimitBackend:   "redis",
		RateLimitRedisAddr: "redis.prod.internal:6379",
	}
}

func randomBytes(n int) []byte {
	// Deterministic but high-entropy enough to pass the weak-key check.
	out := make([]byte, n)
	x := uint64(0xcafebabe_deadbeef)
	for i := 0; i < n; i++ {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = byte(x >> 56)
	}
	return out
}

func bytesRep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func monotonicBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
