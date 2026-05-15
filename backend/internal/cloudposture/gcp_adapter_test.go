package cloudposture

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// generateTestSAKey creates a fresh RSA-2048 key + PKCS8 PEM string
// suitable for the SA JWT flow. Done once per test process.
func generateTestSAKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestGCPAdapter_PassPath(t *testing.T) {
	a := newGCPStub(t, gcpStubData{
		storage:   `{"items":[{"name":"my-bucket","location":"US","iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true}}}]}`,
		instances: `{"items":{"zones/us-central1-a":{"instances":[{"name":"web-1","zone":"https://compute/zones/us-central1-a","serviceAccounts":[{"email":"custom-sa@my-project.iam.gserviceaccount.com"}]}]}}}`,
		firewalls: `{"items":[{"name":"corp-ssh","direction":"INGRESS","sourceRanges":["10.0.0.0/8"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}]}`,
		sinks:     `{"sinks":[{"name":"gcs-export","destination":"storage.googleapis.com/audit-bucket"}]}`,
	})
	results, err := a.Scan(context.Background(), CloudAccount{
		Provider: "gcp", ExternalID: "my-project",
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := indexByID(results)
	for _, want := range []string{"CIS-GCP-5.1", "CIS-GCP-1.4", "CIS-GCP-3.6", "CIS-GCP-2.4"} {
		r, ok := got[want]
		if !ok {
			t.Errorf("missing control %s", want)
			continue
		}
		if r.Status != "pass" {
			t.Errorf("%s expected pass, got %s (evidence=%s)", want, r.Status, r.Evidence)
		}
	}
}

func TestGCPAdapter_FailPath(t *testing.T) {
	a := newGCPStub(t, gcpStubData{
		storage:   `{"items":[{"name":"public-bucket","location":"US","iamConfiguration":{"uniformBucketLevelAccess":{"enabled":false}}}]}`,
		instances: `{"items":{"zones/us-central1-a":{"instances":[{"name":"vm-default","zone":"https://compute/zones/us-central1-a","serviceAccounts":[{"email":"123456-compute@developer.gserviceaccount.com"}]}]}}}`,
		firewalls: `{"items":[{"name":"world-ssh","direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}]}`,
		sinks:     `{"sinks":[]}`,
	})
	results, _ := a.Scan(context.Background(), CloudAccount{
		Provider: "gcp", ExternalID: "my-project",
	})
	got := indexByID(results)
	if got["CIS-GCP-5.1"].Status != "fail" {
		t.Errorf("5.1 expected fail")
	}
	if got["CIS-GCP-1.4"].Status != "fail" {
		t.Errorf("1.4 expected fail")
	}
	if got["CIS-GCP-3.6"].Status != "fail" {
		t.Errorf("3.6 expected fail")
	}
	if got["CIS-GCP-2.4"].Status != "fail" {
		t.Errorf("2.4 expected fail")
	}
}

func TestGCPAdapter_FirewallPortRange(t *testing.T) {
	// Port range 20-25 includes SSH (22) → must fail.
	a := newGCPStub(t, gcpStubData{
		storage:   `{"items":[]}`,
		instances: `{"items":{}}`,
		firewalls: `{"items":[{"name":"port-range","direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["20-25"]}]}]}`,
		sinks:     `{"sinks":[{"name":"x","destination":"y"}]}`,
	})
	results, _ := a.Scan(context.Background(), CloudAccount{
		Provider: "gcp", ExternalID: "my-project",
	})
	got := indexByID(results)
	if got["CIS-GCP-3.6"].Status != "fail" {
		t.Errorf("port-range 20-25: expected fail, got %s", got["CIS-GCP-3.6"].Status)
	}
}

func TestGCPAdapter_ParseRSAPrivateKey_Roundtrip(t *testing.T) {
	pem := generateTestSAKey(t)
	priv, err := parseRSAPrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	if priv.N == nil {
		t.Error("parsed key has nil modulus")
	}
}

func TestGCPAdapter_TokenCachedSecondCall(t *testing.T) {
	keyPEM := generateTestSAKey(t)
	tokCalls := 0
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokCalls++
		w.Write([]byte(`{"access_token":"cached-tok","expires_in":3600}`))
	}))
	defer tokSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":[]}`))
	}))
	defer apiSrv.Close()

	resolver := func(ctx context.Context, _ CloudAccount) (GCPCredentials, error) {
		return GCPCredentials{
			ProjectID:    "p",
			PrivateKeyID: "k",
			PrivateKey:   keyPEM,
			ClientEmail:  "test@p.iam.gserviceaccount.com",
		}, nil
	}
	a := NewGCPAdapter(resolver)
	a.HTTPClient = &http.Client{Transport: gcpRewrite{tokURL: tokSrv.URL, apiURL: apiSrv.URL}}

	for i := 0; i < 3; i++ {
		if _, err := a.Scan(context.Background(), CloudAccount{Provider: "gcp", ExternalID: "p"}); err != nil {
			t.Fatal(err)
		}
	}
	if tokCalls != 1 {
		t.Errorf("token endpoint called %d times, expected 1", tokCalls)
	}
}

// ---- stub plumbing --------------------------------------------------------

type gcpStubData struct {
	storage, instances, firewalls, sinks string
}

func newGCPStub(t *testing.T, data gcpStubData) *GCPAdapter {
	t.Helper()
	keyPEM := generateTestSAKey(t)

	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"stub","expires_in":3600}`))
	}))
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/storage/v1/b"):
			w.Write([]byte(data.storage))
		case strings.Contains(path, "/aggregated/instances"):
			w.Write([]byte(data.instances))
		case strings.Contains(path, "/global/firewalls"):
			w.Write([]byte(data.firewalls))
		case strings.HasSuffix(path, "/sinks"):
			w.Write([]byte(data.sinks))
		default:
			t.Logf("gcp stub: unexpected %s", path)
			w.Write([]byte(`{"items":[]}`))
		}
	}))
	t.Cleanup(func() { tokSrv.Close(); apiSrv.Close() })

	resolver := func(ctx context.Context, _ CloudAccount) (GCPCredentials, error) {
		return GCPCredentials{
			ProjectID:    "my-project",
			PrivateKeyID: "kid-1",
			PrivateKey:   keyPEM,
			ClientEmail:  "test@my-project.iam.gserviceaccount.com",
		}, nil
	}
	a := NewGCPAdapter(resolver)
	a.HTTPClient = &http.Client{Transport: gcpRewrite{tokURL: tokSrv.URL, apiURL: apiSrv.URL}}
	return a
}

type gcpRewrite struct {
	tokURL, apiURL string
}

func (rt gcpRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case r.URL.Host == "oauth2.googleapis.com":
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(rt.tokURL, "http://")
	case r.URL.Host == "storage.googleapis.com",
		r.URL.Host == "compute.googleapis.com",
		r.URL.Host == "logging.googleapis.com",
		r.URL.Host == "iam.googleapis.com":
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(rt.apiURL, "http://")
	}
	return http.DefaultTransport.RoundTrip(r)
}
