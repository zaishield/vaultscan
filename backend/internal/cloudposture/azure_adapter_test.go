package cloudposture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubAzure spins httptest servers for both the OAuth token endpoint
// and the management.azure.com REST surface, drives the adapter, and
// verifies the parsed control results.

func TestAzureAdapter_PassPath(t *testing.T) {
	a := newAzureStub(t, azureStubData{
		storage:   `{"value":[{"id":"/sub/sa1","name":"sa1","location":"westus","properties":{"supportsHttpsTrafficOnly":true}}]}`,
		nsgs:      `{"value":[{"id":"/sub/nsg1","name":"nsg1","location":"westus","properties":{"securityRules":[{"name":"corp-ssh","properties":{"direction":"Inbound","access":"Allow","protocol":"Tcp","destinationPortRange":"22","sourceAddressPrefix":"10.0.0.0/8"}}]}}]}`,
		keyvaults: `{"value":[{"id":"/sub/kv1","name":"kv1","location":"westus","properties":{"enableSoftDelete":true}}]}`,
		pricings:  `{"value":[{"name":"VirtualMachines","properties":{"pricingTier":"Standard"}},{"name":"AppServices","properties":{"pricingTier":"Standard"}},{"name":"SqlServers","properties":{"pricingTier":"Standard"}},{"name":"StorageAccounts","properties":{"pricingTier":"Standard"}},{"name":"KeyVaults","properties":{"pricingTier":"Standard"}}]}`,
	})
	results, err := a.Scan(context.Background(), CloudAccount{
		Provider: "azure", ExternalID: "sub-1",
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, r := range results {
		if r.Status == "manual" {
			t.Errorf("unexpected manual: %+v", r)
		}
	}
	got := indexByID(results)
	if got["CIS-Azure-3.1"].Status != "pass" {
		t.Errorf("3.1 expected pass, got %s", got["CIS-Azure-3.1"].Status)
	}
	if got["CIS-Azure-6.1"].Status != "pass" {
		t.Errorf("6.1 expected pass, got %s", got["CIS-Azure-6.1"].Status)
	}
	if got["CIS-Azure-8.1"].Status != "pass" {
		t.Errorf("8.1 expected pass, got %s", got["CIS-Azure-8.1"].Status)
	}
	if got["CIS-Azure-2.7"].Status != "pass" {
		t.Errorf("2.7 expected pass, got %s", got["CIS-Azure-2.7"].Status)
	}
}

func TestAzureAdapter_FailPath(t *testing.T) {
	a := newAzureStub(t, azureStubData{
		storage:   `{"value":[{"id":"/sub/insecure","name":"insecure","location":"westus","properties":{"supportsHttpsTrafficOnly":false}}]}`,
		nsgs:      `{"value":[{"id":"/sub/badnsg","name":"badnsg","location":"westus","properties":{"securityRules":[{"name":"open-ssh","properties":{"direction":"Inbound","access":"Allow","protocol":"Tcp","destinationPortRange":"22","sourceAddressPrefix":"0.0.0.0/0"}}]}}]}`,
		keyvaults: `{"value":[{"id":"/sub/badkv","name":"badkv","location":"westus","properties":{"enableSoftDelete":false}}]}`,
		pricings:  `{"value":[{"name":"VirtualMachines","properties":{"pricingTier":"Free"}}]}`,
	})
	results, err := a.Scan(context.Background(), CloudAccount{
		Provider: "azure", ExternalID: "sub-1",
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := indexByID(results)
	if got["CIS-Azure-3.1"].Status != "fail" {
		t.Errorf("3.1 expected fail, got %s", got["CIS-Azure-3.1"].Status)
	}
	if got["CIS-Azure-6.1"].Status != "fail" {
		t.Errorf("6.1 expected fail, got %s", got["CIS-Azure-6.1"].Status)
	}
	if got["CIS-Azure-8.1"].Status != "fail" {
		t.Errorf("8.1 expected fail, got %s", got["CIS-Azure-8.1"].Status)
	}
	if got["CIS-Azure-2.7"].Status != "fail" {
		t.Errorf("2.7 expected fail, got %s", got["CIS-Azure-2.7"].Status)
	}
}

func TestAzureAdapter_NSGPortRangeIncludesSSH(t *testing.T) {
	cases := []struct {
		single string
		list   []string
		want   bool
	}{
		{"22", nil, true},
		{"20-30", nil, true},
		{"*", nil, true},
		{"443", nil, false},
		{"", []string{"80", "22-23"}, true},
		{"", []string{"443", "8080"}, false},
	}
	for _, c := range cases {
		if got := portRangeIncludes(c.single, c.list, 22); got != c.want {
			t.Errorf("portRangeIncludes(%q,%v,22)=%v want %v", c.single, c.list, got, c.want)
		}
	}
}

func TestAzureAdapter_TokenCachedSecondCall(t *testing.T) {
	calls := 0
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"cached-token","expires_in":3600}`))
	}))
	defer tokSrv.Close()

	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":[]}`))
	}))
	defer armSrv.Close()

	resolver := func(ctx context.Context, _ CloudAccount) (AzureCredentials, error) {
		return AzureCredentials{TenantID: "t", ClientID: "c", ClientSecret: "s", SubscriptionID: "sub"}, nil
	}
	a := NewAzureAdapter(resolver)
	a.HTTPClient = &http.Client{Transport: azureRewrite{tokURL: tokSrv.URL, armURL: armSrv.URL}}

	for i := 0; i < 3; i++ {
		_, err := a.Scan(context.Background(), CloudAccount{Provider: "azure", ExternalID: "sub"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("token endpoint called %d times, expected 1 (cached)", calls)
	}
}

// ---- stub plumbing --------------------------------------------------------

type azureStubData struct {
	storage   string
	nsgs      string
	keyvaults string
	pricings  string
}

func newAzureStub(t *testing.T, data azureStubData) *AzureAdapter {
	t.Helper()
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"stub-token","expires_in":3600}`))
	}))
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.Contains(path, "Microsoft.Storage/storageAccounts"):
			w.Write([]byte(data.storage))
		case strings.Contains(path, "Microsoft.Network/networkSecurityGroups"):
			w.Write([]byte(data.nsgs))
		case strings.Contains(path, "Microsoft.KeyVault") || strings.Contains(r.URL.RawQuery, "Microsoft.KeyVault"):
			w.Write([]byte(data.keyvaults))
		case strings.Contains(path, "Microsoft.Security/pricings"):
			w.Write([]byte(data.pricings))
		default:
			t.Logf("azure stub got unexpected: %s?%s", path, r.URL.RawQuery)
			w.Write([]byte(`{"value":[]}`))
		}
	}))
	t.Cleanup(func() { tokSrv.Close(); armSrv.Close() })

	resolver := func(ctx context.Context, _ CloudAccount) (AzureCredentials, error) {
		return AzureCredentials{TenantID: "t", ClientID: "c", ClientSecret: "s", SubscriptionID: "sub"}, nil
	}
	a := NewAzureAdapter(resolver)
	a.HTTPClient = &http.Client{Transport: azureRewrite{tokURL: tokSrv.URL, armURL: armSrv.URL}}
	return a
}

type azureRewrite struct {
	tokURL, armURL string
}

func (rt azureRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case strings.HasPrefix(r.URL.Host, "login.microsoftonline.com"):
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(rt.tokURL, "http://")
	case strings.HasPrefix(r.URL.Host, "management.azure.com"):
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(rt.armURL, "http://")
	}
	return http.DefaultTransport.RoundTrip(r)
}

// keep import live for tests above that may marshal payloads.
var _ = json.Marshal
