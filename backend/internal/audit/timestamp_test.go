package audit

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTimestamp_RejectsBadHashLength(t *testing.T) {
	t.Parallel()
	c := NewTSAClient("http://x")
	_, err := c.Timestamp(context.Background(), []byte("short"))
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected length error; got %v", err)
	}
}

func TestTimestamp_TSAReturns200_ParsesSuccessReply(t *testing.T) {
	t.Parallel()
	// Build a minimal valid TimeStampResp: status=0, TimeStampToken
	// is an opaque CMS-shaped blob we just drop in as RawValue.
	dummyToken := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x01}, // INTEGER 1 — placeholder body
		FullBytes:  []byte{0x30, 0x03, 0x02, 0x01, 0x01},
	}
	resp := tsResp{
		Status:         pkiStatusInfo{Status: 0},
		TimeStampToken: dummyToken,
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Errorf("unexpected request content-type: %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		// Sanity: client should have sent a TimeStampReq.
		if len(body) < 10 {
			t.Errorf("request too short: %d bytes", len(body))
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(respDER)
	}))
	defer srv.Close()

	c := NewTSAClient(srv.URL)
	hash := make([]byte, sha256.Size)
	tok, err := c.Timestamp(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Token) == 0 {
		t.Error("expected non-empty token bytes")
	}
}

func TestTimestamp_TSARejection(t *testing.T) {
	t.Parallel()
	resp := tsResp{Status: pkiStatusInfo{Status: 2}} // rejection
	respDER, _ := asn1.Marshal(resp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(respDER)
	}))
	defer srv.Close()
	c := NewTSAClient(srv.URL)
	if _, err := c.Timestamp(context.Background(), make([]byte, 32)); err == nil {
		t.Error("expected TSA-refused error")
	}
}

func TestTimestamp_TSAHTTP500(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", 500)
	}))
	defer srv.Close()
	c := NewTSAClient(srv.URL)
	if _, err := c.Timestamp(context.Background(), make([]byte, 32)); err == nil {
		t.Error("expected error on TSA 500")
	}
}

func TestBuildTSReq_Roundtrip(t *testing.T) {
	t.Parallel()
	hash := sha256.Sum256([]byte("hello"))
	der, err := buildTSReq(hash[:])
	if err != nil {
		t.Fatal(err)
	}
	var got tsReq
	if _, err := asn1.Unmarshal(der, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Errorf("got version %d, want 1", got.Version)
	}
	if string(got.MessageImprint.HashedMessage) != string(hash[:]) {
		t.Errorf("hashed message mismatch")
	}
	if got.Nonce == nil || got.Nonce.Cmp(big.NewInt(0)) <= 0 {
		t.Errorf("nonce missing or zero: %v", got.Nonce)
	}
	if !got.CertReq {
		t.Error("CertReq should be true")
	}
}

func TestNewTSAClient_DefaultURL(t *testing.T) {
	t.Parallel()
	c := NewTSAClient("")
	if c.URL == "" {
		t.Error("default URL should not be empty")
	}
}

func TestWithTrustedRootsPEM_EmptyDisablesVerification(t *testing.T) {
	t.Parallel()
	c, err := NewTSAClient("").WithTrustedRootsPEM(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.TrustedRoots != nil {
		t.Errorf("empty PEM should leave TrustedRoots nil; got non-nil")
	}
}

func TestWithTrustedRootsPEM_RejectsGarbage(t *testing.T) {
	t.Parallel()
	_, err := NewTSAClient("").WithTrustedRootsPEM([]byte("not a pem"))
	if err == nil {
		t.Error("expected error on garbage PEM")
	}
}

func TestExtractCertsFromCMS_RejectsEmptySignedData(t *testing.T) {
	t.Parallel()
	// A valid-looking ContentInfo wrapping an empty SignedData.
	// We expect extractCertsFromCMS to refuse rather than crash.
	_, _, err := extractCertsFromCMS([]byte{0x30, 0x00}) // empty SEQUENCE
	if err == nil {
		t.Error("expected error for empty CMS input")
	}
}

// VerifyChain returning nil when no trust pool is wired preserves
// the dev path. This test guards against a regression where a fresh
// TSAClient suddenly requires a configured pool.
func TestVerifyChain_NilPoolPassesEverything(t *testing.T) {
	t.Parallel()
	c := NewTSAClient("")
	if err := c.VerifyChain([]byte("garbage")); err != nil {
		t.Errorf("nil TrustedRoots should bypass verification, got: %v", err)
	}
}
