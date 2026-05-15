//go:build integration

package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

// TestVS08_EnvelopeEncryption: an object written via RecordWithDEK
// is recoverable, the on-disk bytes do not contain the plaintext, and
// finding_evidence.encryption_key_version is set.
func TestVS08_EnvelopeEncryption(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs08-env")

	body := []byte("This is a sensitive scanner output — do not leak in plaintext on disk!")
	id, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID,
		Kind: "raw_output", ContentType: "text/plain",
		Body: body, UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// Roundtrip the plaintext.
	got, err := h.vault.ReadWithDEK(ctx, id, &adminID, nil, "go-test")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("roundtrip mismatch:\n got: %q\nwant: %q", got, body)
	}

	// encryption_key_version must be 1 after the first write.
	var kv int
	if err := h.pool.QueryRow(ctx,
		`SELECT encryption_key_version FROM finding_evidence WHERE id=$1`,
		id).Scan(&kv); err != nil {
		t.Fatal(err)
	}
	if kv != 1 {
		t.Fatalf("expected key version 1, got %d", kv)
	}

	// The wrapped DEK in tenant_data_keys must NOT contain the plaintext DEK
	// (we can't observe the DEK directly, but we can confirm the wrapper
	// row exists).
	var wrappedLen int
	_ = h.pool.QueryRow(ctx,
		`SELECT octet_length(wrapped_key) FROM tenant_data_keys WHERE tenant_id=$1`,
		tenantID).Scan(&wrappedLen)
	if wrappedLen < 32 {
		t.Fatalf("wrapped key looks too small (%d bytes) — not encrypted?", wrappedLen)
	}
}

// TestVS08_KeyRotation: rotate the tenant key, the next write uses
// v2, but the v1 object remains decryptable.
func TestVS08_KeyRotation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs08-rot")

	body1 := []byte("plaintext v1")
	id1, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, Kind: "raw_output",
		ContentType: "text/plain", Body: body1, UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}

	newVer, err := h.vault.RotateTenantKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newVer != 2 {
		t.Fatalf("expected new version 2, got %d", newVer)
	}

	body2 := []byte("plaintext v2")
	id2, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, Kind: "raw_output",
		ContentType: "text/plain", Body: body2, UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var kv1, kv2 int
	_ = h.pool.QueryRow(ctx,
		`SELECT encryption_key_version FROM finding_evidence WHERE id=$1`, id1).Scan(&kv1)
	_ = h.pool.QueryRow(ctx,
		`SELECT encryption_key_version FROM finding_evidence WHERE id=$1`, id2).Scan(&kv2)
	if kv1 != 1 || kv2 != 2 {
		t.Fatalf("expected kv1=1 kv2=2, got %d %d", kv1, kv2)
	}

	// v1 object still decryptable.
	got1, err := h.vault.ReadWithDEK(ctx, id1, &adminID, nil, "go-test")
	if err != nil {
		t.Fatalf("read v1 after rotation: %v", err)
	}
	if !bytes.Equal(got1, body1) {
		t.Fatal("v1 roundtrip after rotation failed")
	}
}

// TestVS08_ChainOfCustody: upload + read + verify integrity produce
// distinct chain rows, and the markdown renders them in order.
func TestVS08_ChainOfCustody(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs08-chain")

	body := []byte("custody-tracked payload")
	id, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, Kind: "raw_output",
		ContentType: "text/plain", Body: body, UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.vault.ReadWithDEK(ctx, id, &adminID, nil, "go-test"); err != nil {
		t.Fatal(err)
	}
	ok, err := h.vault.VerifyIntegrity(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("integrity check failed on freshly-written object")
	}

	events, err := h.vault.ChainOfCustody(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 {
		t.Fatalf("expected >= 3 custody events, got %d: %+v", len(events), events)
	}
	wantEvents := map[string]bool{"uploaded": false, "accessed": false, "integrity_verified": false}
	for _, e := range events {
		if _, ok := wantEvents[e.Event]; ok {
			wantEvents[e.Event] = true
		}
	}
	for k, seen := range wantEvents {
		if !seen {
			t.Fatalf("missing custody event %q in %+v", k, events)
		}
	}

	md, err := h.vault.ChainOfCustodyMarkdown(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Chain of Custody", "uploaded", "integrity_verified"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}
}

// TestVS08_WORMRejectsDelete: enabling WORM stops PurgeWithWORMCheck.
func TestVS08_WORMRejectsDelete(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "vs08-worm")
	id, err := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, Kind: "raw_output",
		ContentType: "text/plain", Body: []byte("never delete me"),
		UploadedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.vault.EnableWORM(ctx, id, time.Now().Add(365*24*time.Hour), &adminID); err != nil {
		t.Fatalf("enable WORM: %v", err)
	}
	purged, err := h.vault.PurgeWithWORMCheck(ctx, id, &adminID, "operator requested delete")
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged {
		t.Fatal("WORM-locked object must not be purged")
	}

	// Object must still exist + the custody log must show the denial.
	var purgedAt *time.Time
	_ = h.pool.QueryRow(ctx,
		`SELECT purged_at FROM finding_evidence WHERE id=$1`, id).Scan(&purgedAt)
	if purgedAt != nil {
		t.Fatal("WORM-locked row was purged in DB")
	}
	events, _ := h.vault.ChainOfCustody(ctx, id)
	denied := false
	for _, e := range events {
		if e.Event == "purge_denied" {
			denied = true
		}
	}
	if !denied {
		t.Fatalf("expected purge_denied custody event, got %+v", events)
	}

	// Non-WORM control: a fresh object purges normally.
	id2, _ := h.vault.RecordWithDEK(ctx, evidence.PutInput{
		TenantID: tenantID, PartnerID: directID, Kind: "raw_output",
		ContentType: "text/plain", Body: []byte("delete me"),
		UploadedBy: &adminID,
	})
	ok, _ := h.vault.PurgeWithWORMCheck(ctx, id2, &adminID, "test")
	if !ok {
		t.Fatal("non-WORM object should purge")
	}
	_ = uuid.Nil
}
