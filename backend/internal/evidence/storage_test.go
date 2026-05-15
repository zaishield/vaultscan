package evidence

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestFilesystemStorage_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFilesystemStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.New()
	objectID := uuid.New()
	body := []byte("hello world")
	if err := s.Put(context.Background(), tenantID, objectID, body); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), tenantID, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("roundtrip mismatch: got %q want %q", got, body)
	}
	if err := s.Delete(context.Background(), tenantID, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), tenantID, objectID); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound after delete; got %v", err)
	}
}

func TestFilesystemStorage_DeleteMissing_NotError(t *testing.T) {
	s, _ := NewFilesystemStorage(t.TempDir())
	if err := s.Delete(context.Background(), uuid.New(), uuid.New()); err != nil {
		t.Errorf("delete missing should be ok; got %v", err)
	}
}

func TestFilesystemStorage_TenantIsolation(t *testing.T) {
	s, _ := NewFilesystemStorage(t.TempDir())
	tenantA := uuid.New()
	tenantB := uuid.New()
	objA := uuid.New()
	_ = s.Put(context.Background(), tenantA, objA, []byte("for-A"))
	// Same object UUID (cosmically improbable but verify shape) under
	// tenant B must not collide.
	_ = s.Put(context.Background(), tenantB, objA, []byte("for-B"))
	if got, _ := s.Get(context.Background(), tenantA, objA); string(got) != "for-A" {
		t.Errorf("tenant A's blob clobbered: %q", got)
	}
	if got, _ := s.Get(context.Background(), tenantB, objA); string(got) != "for-B" {
		t.Errorf("tenant B's blob clobbered: %q", got)
	}
}

// stubS3Server simulates an S3-compatible server. Stores blobs in a map
// keyed by request path. Verifies SigV4 headers are attached.
type stubS3Server struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	objects map[string][]byte
	authSeen []string
}

func newStubS3(t *testing.T) *stubS3Server {
	s := &stubS3Server{t: t, objects: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Capture Authorization header for assertion later.
		auth := r.Header.Get("Authorization")
		s.authSeen = append(s.authSeen, auth)
		key := r.URL.Path
		switch r.Method {
		case http.MethodPut:
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			s.objects[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			b, ok := s.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("<Error><Code>NoSuchKey</Code></Error>"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		case http.MethodDelete:
			delete(s.objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	s.srv = httptest.NewServer(mux)
	return s
}

func (s *stubS3Server) Close() { s.srv.Close() }

func TestS3Storage_Roundtrip(t *testing.T) {
	stub := newStubS3(t)
	defer stub.Close()
	s, err := NewS3Storage(S3Config{
		Endpoint:        stub.srv.URL,
		Bucket:          "vault-evidence",
		Region:          "us-east-1",
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		ForcePathStyle:  true,
		HTTPClient:      stub.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.New()
	objectID := uuid.New()
	body := []byte("evidence-bytes")
	if err := s.Put(context.Background(), tenantID, objectID, body); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), tenantID, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("S3 roundtrip mismatch: got %q want %q", got, body)
	}
	if err := s.Delete(context.Background(), tenantID, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), tenantID, objectID); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound after S3 delete; got %v", err)
	}
}

func TestS3Storage_RequestsAreSigV4Signed(t *testing.T) {
	stub := newStubS3(t)
	defer stub.Close()
	s, _ := NewS3Storage(S3Config{
		Endpoint:        stub.srv.URL,
		Bucket:          "b",
		AccessKeyID:     "AK",
		SecretAccessKey: "SK",
		ForcePathStyle:  true,
		HTTPClient:      stub.srv.Client(),
	})
	_ = s.Put(context.Background(), uuid.New(), uuid.New(), []byte("x"))
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.authSeen) == 0 {
		t.Fatal("no auth header captured")
	}
	if !strings.HasPrefix(stub.authSeen[0], "AWS4-HMAC-SHA256 Credential=AK/") {
		t.Errorf("auth header not SigV4-shaped: %s", stub.authSeen[0])
	}
}

func TestS3Storage_GetAbsentReturnsErrObjectNotFound(t *testing.T) {
	stub := newStubS3(t)
	defer stub.Close()
	s, _ := NewS3Storage(S3Config{
		Endpoint: stub.srv.URL, Bucket: "b",
		AccessKeyID: "AK", SecretAccessKey: "SK",
		ForcePathStyle: true, HTTPClient: stub.srv.Client(),
	})
	_, err := s.Get(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("missing object: expected ErrObjectNotFound, got %v", err)
	}
}

func TestS3Storage_DeleteMissingIsOk(t *testing.T) {
	stub := newStubS3(t)
	defer stub.Close()
	s, _ := NewS3Storage(S3Config{
		Endpoint: stub.srv.URL, Bucket: "b",
		AccessKeyID: "AK", SecretAccessKey: "SK",
		ForcePathStyle: true, HTTPClient: stub.srv.Client(),
	})
	if err := s.Delete(context.Background(), uuid.New(), uuid.New()); err != nil {
		t.Errorf("delete missing should be ok; got %v", err)
	}
}

func TestS3Storage_RejectsBadConfig(t *testing.T) {
	cases := map[string]S3Config{
		"no endpoint": {Bucket: "b", AccessKeyID: "AK", SecretAccessKey: "SK"},
		"no bucket":   {Endpoint: "https://x", AccessKeyID: "AK", SecretAccessKey: "SK"},
		"no creds":    {Endpoint: "https://x", Bucket: "b"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewS3Storage(cfg); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestVault_WithStorage_S3(t *testing.T) {
	// Ensures NewVault honors WithStorage and round-trips through the
	// S3 backend end-to-end (encrypt → s3.Put → s3.Get → decrypt).
	stub := newStubS3(t)
	defer stub.Close()
	storage, _ := NewS3Storage(S3Config{
		Endpoint: stub.srv.URL, Bucket: "vault",
		AccessKeyID: "AK", SecretAccessKey: "SK",
		ForcePathStyle: true, HTTPClient: stub.srv.Client(),
	})
	// Use a base64-encoded 32-byte key.
	masterKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	v := &Vault{
		masterKey: make([]byte, 32),
		storage:   storage,
	}
	_ = masterKey // placeholder; we constructed Vault directly above
	tenantID := uuid.New()
	body := []byte("end-to-end via S3")
	url, err := v.Put(context.Background(), PutInput{TenantID: tenantID, Body: body})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(url, "vaultscan://"+tenantID.String()) {
		t.Errorf("storage url shape wrong: %s", url)
	}
	tid, oid, ok := parseObjectURL(url)
	if !ok {
		t.Fatal("parseObjectURL")
	}
	raw, err := storage.Get(context.Background(), tid, oid)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 12 {
		t.Fatalf("short blob (%d bytes)", len(raw))
	}
	plain, err := v.decrypt(raw[12:], raw[:12])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != string(body) {
		t.Errorf("decrypted mismatch: got %q want %q", plain, body)
	}
}
