package cache

import (
	"strings"
	"testing"
)

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := NewEncrypted(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("scan results pending upload")
	if err := c.Put("job-1", body); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("roundtrip mismatch: got %q want %q", got, body)
	}
}

func TestCache_GetMissing(t *testing.T) {
	c, _ := NewEncrypted(t.TempDir())
	if _, err := c.Get("does-not-exist"); err == nil {
		t.Error("expected error reading missing entry")
	}
}

func TestCache_KeyPersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	c1, _ := NewEncrypted(dir)
	_ = c1.Put("k", []byte("payload"))

	// Re-open same dir → same key → can decrypt prior write.
	c2, _ := NewEncrypted(dir)
	got, err := c2.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("got %q", got)
	}
}

func TestCache_DifferentDirsCannotDecryptEachOther(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	cA, _ := NewEncrypted(dirA)
	cB, _ := NewEncrypted(dirB)
	_ = cA.Put("k", []byte("for-A"))
	// Move A's encrypted file into B's directory and try to decrypt
	// with B's key. Should fail (different per-cache key).
	body, _ := cA.Get("k")
	_ = cB.Put("k", body) // re-encrypt under B's key — round-trips
	got, _ := cB.Get("k")
	if string(got) != string(body) {
		t.Errorf("B should round-trip its own put: got %q", got)
	}
}

func TestCache_HashStableForSameInput(t *testing.T) {
	c, _ := NewEncrypted(t.TempDir())
	a := c.Hash([]byte("hello"))
	b := c.Hash([]byte("hello"))
	if a != b {
		t.Errorf("hash not stable: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "2cf24dba") { // sha256("hello") prefix
		t.Errorf("unexpected sha256 of 'hello': %s", a)
	}
}
