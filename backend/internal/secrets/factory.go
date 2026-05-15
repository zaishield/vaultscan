// factory.go — config-driven Backend selection. Used by main() to
// construct the right backend based on VAULTSCAN_SECRETS_BACKEND.
package secrets

import (
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FactoryConfig is the projection of internal/config.Config that the
// factory needs. Built by cmd/api/main.go to keep secrets package
// free of a config dependency.
type FactoryConfig struct {
	Backend string  // env | memory | openbao | infisical | awskms

	// Shared
	HTTPClientTimeoutSeconds int

	// OpenBao / Vault
	OpenBaoAddr      string
	OpenBaoMount     string
	OpenBaoNamespace string
	OpenBaoToken     string

	// Infisical
	InfisicalAddr        string
	InfisicalProjectID   string
	InfisicalEnvironment string
	InfisicalToken       string

	// AWS KMS
	AWSKMSRegion        string
	AWSKMSKeyID         string
	AWSKMSAccessKey     string
	AWSKMSSecret        string
	AWSKMSSessionToken  string
	AWSKMSPool          *pgxpool.Pool  // injected by main
}

// NewBackendFromConfig dispatches on cfg.Backend.
func NewBackendFromConfig(cfg FactoryConfig) (Backend, error) {
	switch cfg.Backend {
	case "", "env":
		return EnvBackend{}, nil
	case "memory":
		return NewMemoryBackend(), nil
	case "openbao", "vault":
		return NewOpenBaoBackend(OpenBaoConfig{
			Addr:      cfg.OpenBaoAddr,
			Mount:     cfg.OpenBaoMount,
			Namespace: cfg.OpenBaoNamespace,
			Token:     cfg.OpenBaoToken,
		})
	case "infisical":
		return NewInfisicalBackend(InfisicalConfig{
			Addr:        cfg.InfisicalAddr,
			ProjectID:   cfg.InfisicalProjectID,
			Environment: cfg.InfisicalEnvironment,
			Token:       cfg.InfisicalToken,
		})
	case "awskms":
		return NewAWSKMSBackend(AWSKMSConfig{
			Pool:            cfg.AWSKMSPool,
			Region:          cfg.AWSKMSRegion,
			KeyID:           cfg.AWSKMSKeyID,
			AccessKeyID:     cfg.AWSKMSAccessKey,
			SecretAccessKey: cfg.AWSKMSSecret,
			SessionToken:    cfg.AWSKMSSessionToken,
		})
	default:
		return nil, fmt.Errorf("secrets: unknown backend %q (want: env|memory|openbao|infisical|awskms)", cfg.Backend)
	}
}

// keep import live
var _ = strconv.Atoi
