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

	SecretsBackend     string  // env | memory | openbao | infisical | awskms
	SecretsAddr        string
	SecretsToken       string

	// OpenBao / HashiCorp Vault.
	SecretsOpenBaoMount     string
	SecretsOpenBaoNamespace string

	// Infisical.
	SecretsInfisicalProjectID   string
	SecretsInfisicalEnvironment string

	// AWS KMS (uses ObjectStore* AWS creds for SigV4).
	SecretsKMSRegion        string
	SecretsKMSKeyID         string
	SecretsKMSAccessKey     string
	SecretsKMSSecretKey     string
	SecretsKMSSessionToken  string

	EvidenceMasterKey  string  // base64; AES-256 master key for evidence at-rest envelope encryption
	EvidenceURLTTL     time.Duration

	// EvidenceBackend selects the storage adapter the evidence vault uses.
	//   "filesystem" — local disk (dev / single-node only)
	//   "s3"         — S3-compatible object store (AWS S3, MinIO, Ceph,
	//                  R2, Backblaze, Wasabi). Reads ObjectStore* fields.
	EvidenceBackend         string
	EvidenceFilesystemRoot  string
	// EvidenceS3ForcePathStyle = true (default) for MinIO/Ceph/AWS path
	// addressing; false for AWS virtual-host (https://bucket.s3.<region>.amazonaws.com/key).
	EvidenceS3ForcePathStyle bool
	// EvidenceS3SSE: optional X-Amz-Server-Side-Encryption header value
	// ("AES256" | "aws:kms" | ""). Adds a second SSE layer on top of the
	// vault's envelope encryption.
	EvidenceS3SSE           string

	// ScannerPullKey is the 32-byte (base64) KEK that wraps scanner image-pull
	// credentials. Distinct from EvidenceMasterKey so a vault-key rotation
	// doesn't disturb scanner credentials and vice versa.
	ScannerPullKey     string

	// Agent-gateway server cert (presented to agents). When both paths are
	// empty AND VAULTSCAN_AGENT_GW_TLS is "auto", the gateway mints a self-
	// signed cert at boot (dev only).
	AgentGatewayCertPath string
	AgentGatewayKeyPath  string

	ScannerImageRegistry string

	// APIPublicURLValue is the externally-reachable URL of the API service,
	// used by sibling services (scanner-worker, analytics-worker) to fetch
	// the orchestrator public key.
	APIPublicURLValue string

	BrandingDefault    string  // partner slug treated as the default if no domain matches
	CORSAllowedOrigins []string

	RateLimitRPS       int
	EmergencyStopMaxLatencySeconds int

	// RateLimit backend selection. "" or "memory" → in-process token
	// bucket (single-pod only). "redis" → Redis sliding window.
	RateLimitBackend       string
	RateLimitRedisAddr     string
	RateLimitRedisPassword string
	RateLimitRedisDB       int
	// RateLimitWindowSec is the rolling window for the Redis sliding-
	// window backend. Memory backend always treats limit as RPS.
	RateLimitWindowSec     int
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
		SecretsOpenBaoMount:     getenv("VAULTSCAN_SECRETS_OPENBAO_MOUNT", "kv"),
		SecretsOpenBaoNamespace: os.Getenv("VAULTSCAN_SECRETS_OPENBAO_NAMESPACE"),
		SecretsInfisicalProjectID:   os.Getenv("VAULTSCAN_SECRETS_INFISICAL_PROJECT_ID"),
		SecretsInfisicalEnvironment: getenv("VAULTSCAN_SECRETS_INFISICAL_ENV", "prod"),
		SecretsKMSRegion:       os.Getenv("VAULTSCAN_SECRETS_KMS_REGION"),
		SecretsKMSKeyID:        os.Getenv("VAULTSCAN_SECRETS_KMS_KEY_ID"),
		SecretsKMSAccessKey:    os.Getenv("VAULTSCAN_SECRETS_KMS_ACCESS_KEY"),
		SecretsKMSSecretKey:    os.Getenv("VAULTSCAN_SECRETS_KMS_SECRET_KEY"),
		SecretsKMSSessionToken: os.Getenv("VAULTSCAN_SECRETS_KMS_SESSION_TOKEN"),
		EvidenceMasterKey: getenv("VAULTSCAN_EVIDENCE_MASTER_KEY",
			"ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA="),
		EvidenceBackend:        getenv("VAULTSCAN_EVIDENCE_BACKEND", "filesystem"),
		EvidenceFilesystemRoot: os.Getenv("VAULTSCAN_EVIDENCE_FS_ROOT"),
		EvidenceS3ForcePathStyle: getenv("VAULTSCAN_EVIDENCE_S3_FORCE_PATH_STYLE", "true") == "true",
		EvidenceS3SSE:          os.Getenv("VAULTSCAN_EVIDENCE_S3_SSE"),
		ScannerPullKey: getenv("VAULTSCAN_SCANNER_PULL_KEY",
			"ZGV2LXNjYW5uZXItcHVsbC1tYXN0ZXIta2V5LTAwMDA="),
		AgentGatewayCertPath: os.Getenv("VAULTSCAN_AGENT_GW_CERT"),
		AgentGatewayKeyPath:  os.Getenv("VAULTSCAN_AGENT_GW_KEY"),
		EvidenceURLTTL:       parseDuration("VAULTSCAN_EVIDENCE_URL_TTL", 5*time.Minute),
		ScannerImageRegistry: getenv("VAULTSCAN_SCANNER_REGISTRY", "registry.zaishield.com/vaultscan/scanners"),
		APIPublicURLValue:    getenv("VAULTSCAN_API_PUBLIC_URL", "http://api:8080"),
		BrandingDefault:      getenv("VAULTSCAN_BRANDING_DEFAULT", "zaishield-direct"),
		CORSAllowedOrigins:   splitList(getenv("VAULTSCAN_CORS_ALLOWED_ORIGINS",
			"http://localhost:5173,http://localhost:3000")),
		RateLimitRPS:                   parseInt("VAULTSCAN_RATE_LIMIT_RPS", 100),
		EmergencyStopMaxLatencySeconds: parseInt("VAULTSCAN_EMERGENCY_STOP_MAX_LATENCY", 30),
		RateLimitBackend:       getenv("VAULTSCAN_RATE_LIMIT_BACKEND", "memory"),
		RateLimitRedisAddr:     os.Getenv("VAULTSCAN_RATE_LIMIT_REDIS_ADDR"),
		RateLimitRedisPassword: os.Getenv("VAULTSCAN_RATE_LIMIT_REDIS_PASSWORD"),
		RateLimitRedisDB:       parseInt("VAULTSCAN_RATE_LIMIT_REDIS_DB", 0),
		RateLimitWindowSec:     parseInt("VAULTSCAN_RATE_LIMIT_WINDOW_SEC", 60),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("VAULTSCAN_DATABASE_URL is required")
	}
	if err := c.validateProduction(); err != nil {
		return nil, err
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
