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

	// Region is the deployment-zone code (ae|eu|uk|in|us|sg|au|jp) the
	// pod is running in. Read by data-residency enforcement to refuse
	// cross-region writes when a tenant is pinned. Empty = single-
	// region deployment; residency enforcement is a no-op.
	Region             string

	DatabaseURL        string
	// DatabaseReplicaURL is the read-only Postgres replica. Empty =
	// no replica configured; all reads go to the primary.
	DatabaseReplicaURL string
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
	// RateLimitFailOpen toggles fail-open vs fail-closed when the
	// limiter backend errors (e.g. Redis unreachable). Default is
	// false (fail closed → 503) which closes a known DoS vector
	// where an attacker drops Redis to remove rate limits. Set to
	// true only in environments where availability outweighs the
	// brief unprotected window during a Redis blip.
	RateLimitFailOpen      bool

	// Debug / pprof server. Mounted on a separate addr so the
	// production network policy can lock it down independently of
	// the public API. Empty addr disables the server entirely.
	DebugAddr  string
	DebugToken string

	// APIVersion is the build-time release version exposed via
	// the X-API-Version response header so clients can detect
	// rolling-deploy version skew.
	APIVersion string

	// TSATrustedRootsPath points at a PEM bundle of CAs trusted to
	// sign RFC 3161 timestamp tokens. When unset, the TSAClient
	// returns tokens without chain validation (acceptable for
	// dev; refused in production via the production_guard). When
	// set, every successful Timestamp() call additionally validates
	// the embedded cert chain back to one of these roots.
	TSATrustedRootsPath string

	// PerTenantRateLimitMultiplier scales the per-identity RPS to
	// build a per-tenant ceiling (e.g. 5x means a tenant collectively
	// gets 5× the single-user limit). 0 disables the per-tenant cap.
	PerTenantRateLimitMultiplier int

	// DefaultPartnerSlug is the partner used as a fallback for
	// operations that don't carry a partner_id (admin tools,
	// platform-wide schedules, uploads via the operator console).
	// Resolved to a real partner_id at boot; if the slug doesn't
	// exist the API still starts but those handlers return a
	// clear error. Default matches migration 0010's seeded
	// "zaishield-direct" partner.
	DefaultPartnerSlug string

	// CDNMode selects the brand-asset signed-URL strategy:
	//   disabled    — legacy: portal fetches via the evidence-vault
	//                 signed-URL endpoint on every page load
	//   prefix      — naive prefix swap onto CDNPublicBase
	//                 (Cloudflare / public-CDN style)
	//   cloudfront  — AWS CloudFront canned-policy signed URL
	// See internal/branding/cdn.go for the design notes.
	CDNMode           string
	CDNPublicBase     string
	CDNSignedTTL      time.Duration
	CDNKeyPairID      string
	CDNPrivateKeyPath string
}

func Load() (*Config, error) {
	c := &Config{
		Env:               getenv("VAULTSCAN_ENV", "development"),
		APIAddr:           getenv("VAULTSCAN_API_ADDR", ":8080"),
		Region:            getenv("VAULTSCAN_REGION", ""),
		AgentGatewayAddr:  getenv("VAULTSCAN_AGENT_GATEWAY_ADDR", ":8443"),
		OrchestratorAddr:  getenv("VAULTSCAN_ORCH_ADDR", ":8090"),
		DatabaseURL:       getenv("VAULTSCAN_DATABASE_URL",
			"postgres://vaultscan:vaultscan@localhost:5432/vaultscan?sslmode=disable"),
		DatabaseReplicaURL: getenv("VAULTSCAN_DATABASE_REPLICA_URL", ""),
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
		RateLimitFailOpen:      parseBool("VAULTSCAN_RATE_LIMIT_FAIL_OPEN", false),

		// Empty addr → debug server disabled. localhost-only is the
		// safe default: ops port-forwards into the pod when they need
		// pprof. Set to ":6060" in production once a non-empty token
		// is in place.
		DebugAddr:                    getenv("VAULTSCAN_DEBUG_ADDR", ""),
		DebugToken:                   os.Getenv("VAULTSCAN_DEBUG_TOKEN"),
		PerTenantRateLimitMultiplier: parseInt("VAULTSCAN_RATE_LIMIT_TENANT_MULTIPLIER", 10),
		APIVersion:                   getenv("VAULTSCAN_API_VERSION", "dev"),
		TSATrustedRootsPath:          os.Getenv("VAULTSCAN_TSA_TRUSTED_ROOTS_PATH"),
		DefaultPartnerSlug:           getenv("VAULTSCAN_DEFAULT_PARTNER_SLUG", "zaishield-direct"),
		CDNMode:                      getenv("VAULTSCAN_CDN_MODE", "disabled"),
		CDNPublicBase:                os.Getenv("VAULTSCAN_CDN_PUBLIC_BASE"),
		CDNSignedTTL:                 parseDuration("VAULTSCAN_CDN_SIGNED_TTL", time.Hour),
		CDNKeyPairID:                 os.Getenv("VAULTSCAN_CDN_KEY_PAIR_ID"),
		CDNPrivateKeyPath:            os.Getenv("VAULTSCAN_CDN_PRIVATE_KEY_PATH"),
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
		n, err := strconv.Atoi(v)
		if err != nil {
			// A misconfigured env var that silently falls back to
			// the default is a production trap (operator thinks
			// they raised the pool to 128 conns; actually still
			// at 32). Emit to stderr so the boot log shows the
			// mistake. Loud-and-continue is the right trade-off:
			// we don't crash on a typo in a tunable, but we
			// don't pretend everything's fine either.
			fmt.Fprintf(os.Stderr,
				"vaultscan: %s=%q not parseable as int (%v); using default %d\n",
				k, v, err, def)
			return def
		}
		return n
	}
	return def
}

// parseBool reads a boolean env var. Accepts the common forms:
// "1"/"0", "true"/"false", "on"/"off", "yes"/"no" (case-insensitive).
// Anything else falls back to def — a strict parser would be nice
// but the API surface tolerates the loose form historically.
func parseBool(k string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "on", "yes", "y", "t":
		return true
	case "0", "false", "off", "no", "n", "f":
		return false
	}
	return def
}

func parseDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"vaultscan: %s=%q not parseable as duration (%v); using default %s\n",
				k, v, err, def)
			return def
		}
		return d
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
