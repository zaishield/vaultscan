package secrets

import (
	"context"
	"testing"
)

func TestEnvBackend_KeyEncoding(t *testing.T) {
	t.Parallel()
	b := EnvBackend{}
	cases := map[string]string{
		"integrations/jira/api-token": "VAULTSCAN_SECRET_INTEGRATIONS_JIRA_API_TOKEN",
		"secret/db/url":               "VAULTSCAN_SECRET_DB_URL",
		"signing.keys/cloud":          "VAULTSCAN_SECRET_SIGNING_KEYS_CLOUD",
	}
	for ref, want := range cases {
		if got := b.envKey(ref); got != want {
			t.Errorf("envKey(%q) = %q; want %q", ref, got, want)
		}
	}
}

func TestMemoryBackend_RoundTrip(t *testing.T) {
	t.Parallel()
	b := NewMemoryBackend()
	ctx := context.Background()
	if err := b.Put(ctx, "foo/bar", "secret"); err != nil {
		t.Fatal(err)
	}
	v, err := b.Get(ctx, "foo/bar")
	if err != nil || v != "secret" {
		t.Fatalf("Get returned (%q, %v)", v, err)
	}
	if _, err := b.Get(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing ref")
	}
}

func TestService_NilSafe(t *testing.T) {
	t.Parallel()
	var s *Service
	if _, err := s.Get(context.Background(), "x"); err == nil {
		t.Fatal("nil Service must error, not panic")
	}
}
