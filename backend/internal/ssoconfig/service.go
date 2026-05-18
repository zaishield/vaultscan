// Package ssoconfig manages per-tenant SAML / OIDC IdP federation
// settings — the "self-serve SSO" endpoint the customer admin uses
// to wire their IdP (Okta / Entra / Auth0 / Keycloak / Google / etc).
//
// Previously this lived inside the branding endpoint, which was
// both wrong (security config, not branding) and undiscoverable.
// 0061 splits it into its own table + handler.

package ssoconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
)

// Config is the public view of one tenant's SSO config. The
// `client_secret` is NEVER returned through this API — callers
// receive a placeholder + must rotate it explicitly if they want
// to replace it.
type Config struct {
	TenantID       uuid.UUID         `json:"tenant_id"`
	ProviderType   string            `json:"provider_type"`     // saml | oidc | none
	Enabled        bool              `json:"enabled"`
	MetadataXML    string            `json:"metadata_xml,omitempty"`
	DiscoveryURL   string            `json:"discovery_url,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	ClientSecretSet bool             `json:"client_secret_set"`
	ClaimMapping   map[string]string `json:"claim_mapping"`
	LastTestedAt   *time.Time        `json:"last_tested_at,omitempty"`
	LastTestOK     *bool             `json:"last_test_ok,omitempty"`
	LastTestError  string            `json:"last_test_error,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// SetInput is the upsert payload. ClientSecret is optional: an
// empty string leaves the stored secret untouched; an explicit
// `"-"` rotates it to empty (clears).
type SetInput struct {
	ProviderType  string            `json:"provider_type"`
	Enabled       bool              `json:"enabled"`
	MetadataXML   string            `json:"metadata_xml,omitempty"`
	DiscoveryURL  string            `json:"discovery_url,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
	ClientSecret  string            `json:"client_secret,omitempty"`
	ClaimMapping  map[string]string `json:"claim_mapping,omitempty"`
}

// ErrInvalidProvider is returned when an upsert specifies a
// provider_type the platform doesn't recognise.
var ErrInvalidProvider = errors.New("ssoconfig: provider_type must be saml | oidc | none")

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// Get returns the current config for a tenant. If no row exists
// the returned Config has provider_type="none" + enabled=false.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Config, error) {
	var (
		c     Config
		claim []byte
		clientSecret string
	)
	c.TenantID = tenantID
	err := s.pool.QueryRow(ctx, `
		SELECT provider_type, enabled, COALESCE(metadata_xml,''),
		       COALESCE(discovery_url,''), COALESCE(client_id,''),
		       COALESCE(client_secret,''), claim_mapping,
		       last_tested_at, last_test_ok, COALESCE(last_test_error,''),
		       updated_at
		  FROM tenant_sso_config WHERE tenant_id = $1`, tenantID).
		Scan(&c.ProviderType, &c.Enabled, &c.MetadataXML,
			&c.DiscoveryURL, &c.ClientID, &clientSecret, &claim,
			&c.LastTestedAt, &c.LastTestOK, &c.LastTestError,
			&c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// First read for a tenant — return the empty / disabled default.
		return &Config{
			TenantID:     tenantID,
			ProviderType: "none",
			ClaimMapping: map[string]string{"email": "email", "name": "name", "roles": "groups"},
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ssoconfig: read: %w", err)
	}
	c.ClientSecretSet = clientSecret != ""
	if len(claim) > 0 {
		_ = json.Unmarshal(claim, &c.ClaimMapping)
	}
	return &c, nil
}

// Set upserts the tenant's SSO config. Validates provider_type,
// requires the matching metadata/discovery field, and emits an
// audit event. ClientSecret semantics:
//   - empty   → leave existing secret untouched
//   - "-"     → clear the secret (rotate to empty)
//   - other   → replace the secret with the new value
func (s *Service) Set(ctx context.Context, tenantID uuid.UUID, in SetInput, actor *uuid.UUID) (*Config, error) {
	switch in.ProviderType {
	case "saml":
		if in.MetadataXML == "" {
			return nil, errors.New("ssoconfig: saml requires metadata_xml")
		}
	case "oidc":
		if in.DiscoveryURL == "" || in.ClientID == "" {
			return nil, errors.New("ssoconfig: oidc requires discovery_url + client_id")
		}
	case "none":
		// disabling is fine; clear the type-specific fields below
	default:
		return nil, ErrInvalidProvider
	}

	claim := in.ClaimMapping
	if claim == nil {
		claim = map[string]string{"email": "email", "name": "name", "roles": "groups"}
	}
	claimBytes, _ := json.Marshal(claim)

	// Read existing secret so we know whether to preserve it.
	var existing string
	_ = s.pool.QueryRow(ctx,
		`SELECT COALESCE(client_secret,'') FROM tenant_sso_config WHERE tenant_id=$1`,
		tenantID).Scan(&existing)
	newSecret := existing
	if in.ClientSecret == "-" {
		newSecret = ""
	} else if in.ClientSecret != "" {
		newSecret = in.ClientSecret
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_sso_config(tenant_id, provider_type, enabled,
		    metadata_xml, discovery_url, client_id, client_secret,
		    claim_mapping, updated_at)
		VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''), NULLIF($6,''),
		        NULLIF($7,''), $8::jsonb, now())
		ON CONFLICT (tenant_id) DO UPDATE
		   SET provider_type = EXCLUDED.provider_type,
		       enabled       = EXCLUDED.enabled,
		       metadata_xml  = EXCLUDED.metadata_xml,
		       discovery_url = EXCLUDED.discovery_url,
		       client_id     = EXCLUDED.client_id,
		       client_secret = EXCLUDED.client_secret,
		       claim_mapping = EXCLUDED.claim_mapping,
		       updated_at    = now()`,
		tenantID, in.ProviderType, in.Enabled,
		in.MetadataXML, in.DiscoveryURL, in.ClientID, newSecret,
		string(claimBytes)); err != nil {
		return nil, fmt.Errorf("ssoconfig: upsert: %w", err)
	}

	_ = s.audit.Record(ctx, audit.Entry{
		Event:    "tenant.sso_configured",
		TenantID: &tenantID, ActorID: actor,
		Payload: map[string]any{
			"provider_type": in.ProviderType,
			"enabled":       in.Enabled,
			"secret_rotated": in.ClientSecret != "",
		},
	})
	return s.Get(ctx, tenantID)
}
