// credentials.go — bridges from CloudAccount.CredentialRef to the
// per-provider credential structs the adapters consume.
//
// Each resolver:
//   1. Pulls the raw secret payload from secrets.Service.Get(ref).
//   2. Decodes the JSON shape that provider expects.
//   3. Returns the provider-specific credential struct.
//
// This is the only seam where the secrets backend touches cloud creds —
// the adapters themselves never see secrets.Service.
package cloudposture

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zaishield/vaultscan/backend/internal/secrets"
)

// SecretsBackedAWSResolver returns a resolver that pulls JSON of shape
// {"access_key_id":"...","secret_access_key":"...","session_token":""}
// from the secrets backend.
func SecretsBackedAWSResolver(svc *secrets.Service) AWSCredentialsResolver {
	return func(ctx context.Context, account CloudAccount) (AWSCredentials, error) {
		raw, err := svc.Get(ctx, account.CredentialRef)
		if err != nil {
			return AWSCredentials{}, fmt.Errorf("aws creds: %w", err)
		}
		var c struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token,omitempty"`
		}
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return AWSCredentials{}, fmt.Errorf("aws creds: parse json: %w", err)
		}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return AWSCredentials{}, fmt.Errorf("aws creds: missing access_key_id or secret_access_key")
		}
		return AWSCredentials{
			AccessKeyID:     c.AccessKeyID,
			SecretAccessKey: c.SecretAccessKey,
			SessionToken:    c.SessionToken,
		}, nil
	}
}

// SecretsBackedAzureResolver expects JSON of shape
// {"tenant_id":"...","client_id":"...","client_secret":"...","subscription_id":"..."}
func SecretsBackedAzureResolver(svc *secrets.Service) AzureCredentialsResolver {
	return func(ctx context.Context, account CloudAccount) (AzureCredentials, error) {
		raw, err := svc.Get(ctx, account.CredentialRef)
		if err != nil {
			return AzureCredentials{}, fmt.Errorf("azure creds: %w", err)
		}
		var c AzureCredentials
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return AzureCredentials{}, fmt.Errorf("azure creds: parse json: %w", err)
		}
		// Subscription comes from the cloud_accounts row's external_id
		// when not embedded in the secret blob.
		if c.SubscriptionID == "" {
			c.SubscriptionID = account.ExternalID
		}
		if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
			return AzureCredentials{}, fmt.Errorf("azure creds: missing tenant_id/client_id/client_secret")
		}
		if c.SubscriptionID == "" {
			return AzureCredentials{}, fmt.Errorf("azure creds: missing subscription_id (and account.ExternalID empty)")
		}
		return c, nil
	}
}

// SecretsBackedGCPResolver expects the raw service-account JSON exactly
// as Google issues it (gcloud iam service-accounts keys create ...).
func SecretsBackedGCPResolver(svc *secrets.Service) GCPCredentialsResolver {
	return func(ctx context.Context, account CloudAccount) (GCPCredentials, error) {
		raw, err := svc.Get(ctx, account.CredentialRef)
		if err != nil {
			return GCPCredentials{}, fmt.Errorf("gcp creds: %w", err)
		}
		var c GCPCredentials
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return GCPCredentials{}, fmt.Errorf("gcp creds: parse json: %w", err)
		}
		if c.PrivateKey == "" || c.ClientEmail == "" || c.ProjectID == "" {
			return GCPCredentials{}, fmt.Errorf("gcp creds: missing private_key / client_email / project_id")
		}
		return c, nil
	}
}
