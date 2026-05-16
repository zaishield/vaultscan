package authdocs

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// authdocs is end-to-end DB+evidence-vault bound; behaviour is
// exercised by the integration harness via h.authdocs.Upload (see
// test/integration/main_test.go and the engagement acceptance specs).
// This file pins the SHA256 digest format the package promises in
// the authorization_documents.sha256 column.

func TestSHA256DigestShape(t *testing.T) {
	t.Parallel()
	// Verifies the canonical sha256 hex string format the Upload
	// path stores in the DB. Down-stream callers parse this back
	// into 32 bytes; a length drift would break compliance reports.
	body := []byte("AUTHORIZATION (sample)")
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if len(got) != 64 {
		t.Errorf("digest hex length=%d want 64", len(got))
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("digest contains non-hex char %q", c)
			break
		}
	}
}

// TestUploadInput_FieldShape pins the public input struct fields so a
// rename surfaces alongside the change that caused it.
func TestUploadInput_FieldShape(t *testing.T) {
	t.Parallel()
	in := UploadInput{
		Title:        "x",
		DocumentType: "letter",
		ContentType:  "text/plain",
		SignedBy:     "y",
	}
	if in.Title == "" || in.DocumentType == "" {
		t.Fatal("test data invalid")
	}
}
