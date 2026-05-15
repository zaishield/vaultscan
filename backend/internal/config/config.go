// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env                string
	APIAddr            string
	AgentGatewayAddr   string
	OrchestratorAddr   string

	DatabaseURL        string
	OpenSearchURL      string
	EventBusURL        string
	ObjectStoreURL     string
	ObjectStoreBucket  string
	ObjectStoreRegion  string
	ObjectStoreKey     string
	ObjectStoreSecret  string

	KeycloakIssuer     string
	KeycloakAudience   string
	JWTPublicKeyPEM    string
	JWTSharedSecret    string  // fallback HS256 for local dev only

	JobSigningKeyPEM   string  // RSA private key for cloud → agent job signing
	JobSigningKeyID    string

	SecretsBackend     string  // openbao | infisical | env
	SecretsAddr        string
	SecretsToken       string

	EvidenceMasterKey  string  // base64; AES-256 master key for evidence at-rest envelope encryption
	EvidenceURLTTL     time.Duration

	ScannerImageRegistry string

	// APIPublicURLValue is the externally-reachable URL of the API service,
	// used by sibling services (scanner-worker, analytics-worker) to fetch
	// the orchestrator public key.
	APIPublicURLValue string

	BrandingDefault    string  // partner slug treated as the default if no domain matches
	CORSAllowedOrigins []string

	RateLimitRPS       int
	EmergencyStopMaxLatencySeconds int
}

func Load() (*Config, error) {
	c := &Config{
		Env:               getenv("VAULTSCAN_ENV", "development"),
		APIAddr:           getenv("VAULTSCAN_API_ADDR", ":8080"),
		AgentGatewayAddr:  getenv("VAULTSCAN_AGENT_GATEWAY_ADDR", ":8443"),
		OrchestratorAddr:  getenv("VAULTSCAN_ORCH_ADDR", ":8090"),
		DatabaseURL:       getenv("VAULTSCAN_DATABASE_URL",
			"postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable"),
		OpenSearchURL:     getenv("VAULTSCAN_OPENSEARCH_URL", "http://localhost:9200"),
		EventBusURL:       getenv("VAULTSCAN_EVENTBUS_URL", "nats://localhost:4222"),
		ObjectStoreURL:    getenv("VAULTSCAN_OBJECT_STORE_URL", "http://localhost:9000"),
		ObjectStoreBucket: getenv("VAULTSCAN_OBJECT_STORE_BUCKET", "vaultscan-evidence"),
		ObjectStoreRegion: getenv("VAULTSCAN_OBJECT_STORE_REGION", "us-east-1"),
		ObjectStoreKey:    getenv("VAULTSCAN_OBJECT_STORE_KEY", "vaultscan"),
		ObjectStoreSecret: getenv("VAULTSCAN_OBJECT_STORE_SECRET", "vaultscan-dev-secret"),
		KeycloakIssuer:    getenv("VAULTSCAN_KEYCLOAK_ISSUER", "http://localhost:8081/realms/vaultscan"),
		KeycloakAudience:  getenv("VAULTSCAN_KEYCLOAK_AUDIENCE", "vaultscan-portal"),
		JWTSharedSecret:   getenv("VAULTSCAN_JWT_SECRET", "dev-only-shared-secret-change-me"),
		JWTPublicKeyPEM:   os.Getenv("VAULTSCAN_JWT_PUBLIC_KEY"),
		JobSigningKeyPEM:  os.Getenv("VAULTSCAN_JOB_SIGNING_KEY"),
		JobSigningKeyID:   getenv("VAULTSCAN_JOB_SIGNING_KEY_ID", "dev-key-1"),
		SecretsBackend:    getenv("VAULTSCAN_SECRETS_BACKEND", "env"),
		SecretsAddr:       os.Getenv("VAULTSCAN_SECRETS_ADDR"),
		SecretsToken:      os.Getenv("VAULTSCAN_SECRETS_TOKEN"),
		EvidenceMasterKey: getenv("VAULTSCAN_EVIDENCE_MASTER_KEY",
			"ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA="),
		EvidenceURLTTL:       parseDuration("VAULTSCAN_EVIDENCE_URL_TTL", 5*time.Minute),
		ScannerImageRegistry: getenv("VAULTSCAN_SCANNER_REGISTRY", "registry.zaishield.com/vaultscan/scanners"),
		APIPublicURLValue:    getenv("VAULTSCAN_API_PUBLIC_URL", "http://api:8080"),
		BrandingDefault:      getenv("VAULTSCAN_BRANDING_DEFAULT", "zaishield-direct"),
		CORSAllowedOrigins:   splitList(getenv("VAULTSCAN_CORS_ALLOWED_ORIGINS",
			"http://localhost:5173,http://localhost:3000")),
		RateLimitRPS:                   parseInt("VAULTSCAN_RATE_LIMIT_RPS", 100),
		EmergencyStopMaxLatencySeconds: parseInt("VAULTSCAN_EMERGENCY_STOP_MAX_LATENCY", 30),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("VAULTSCAN_DATABASE_URL is required")
	}
	return c, nil
}

// APIPublicURL returns the externally-reachable API URL, with the trailing
// slash trimmed so callers can append paths directly.
func (c *Config) APIPublicURL() string {
	return strings.TrimRight(c.APIPublicURLValue, "/")
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func parseDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
