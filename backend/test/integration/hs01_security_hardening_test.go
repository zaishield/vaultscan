//go:build integration

package integration

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// TestHS01_BruteforceShieldLocksIP: 25 failures from one IP locks it; the
// 26th attempt sees IsLocked=true.
func TestHS01_BruteforceShieldLocksIP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shield := auth.NewBruteforceShield(h.pool)
	shield.Threshold = 5 // shrink for test
	ip := net.ParseIP("203.0.113.7")

	for i := 0; i < shield.Threshold-1; i++ {
		locked, err := shield.RecordFailure(ctx, ip, fmt.Sprintf("victim%d@example", i))
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatalf("locked early at attempt %d", i+1)
		}
	}
	// Crossing the threshold locks the IP.
	locked, err := shield.RecordFailure(ctx, ip, "victim@example")
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatalf("expected lock at threshold %d, didn't trip", shield.Threshold)
	}
	isLocked, until, err := shield.IsLocked(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	if !isLocked {
		t.Fatal("IsLocked must report true after threshold")
	}
	if until.IsZero() {
		t.Fatal("locked_until missing")
	}

	// Unlock + verify gone.
	if err := shield.Unlock(ctx, ip); err != nil {
		t.Fatal(err)
	}
	again, _, _ := shield.IsLocked(ctx, ip)
	if again {
		t.Fatal("IsLocked must report false after unlock")
	}
}

// TestHS01_CompromisedPasswordCheck: load a bucket, then refuse a password
// matching that bucket.
func TestHS01_CompromisedPasswordCheck(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shield := auth.NewBruteforceShield(h.pool)

	pw := "password123"
	sum := sha1.Sum([]byte(pw))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	loaded, err := shield.LoadCompromisedBuckets(ctx, prefix,
		[]byte(suffix+":987654\n"+strings.Repeat("0", 35)+":1\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded < 2 {
		t.Fatalf("expected to load 2 rows, got %d", loaded)
	}

	bad, count, err := shield.IsPasswordCompromised(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !bad {
		t.Fatal("password123 must register as compromised after loading")
	}
	if count != 987654 {
		t.Fatalf("expected seen_count=987654, got %d", count)
	}

	// A novel password must NOT match.
	novel, _, _ := shield.IsPasswordCompromised(ctx, "Tr0ub4dor&3-vaultscan-novel")
	if novel {
		t.Fatal("novel password reported as compromised")
	}
}

// TestHS01_AuditLogsImmutabilityTrigger: UPDATE / DELETE on audit_logs is
// rejected at the trigger level — defense in depth beyond REVOKE.
func TestHS01_AuditLogsImmutabilityTrigger(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, _ := h.makeTenant(t, "hs01-immut")
	var rowID int64
	if err := h.pool.QueryRow(ctx, `
		SELECT id FROM audit_logs
		 WHERE tenant_id=$1 ORDER BY id LIMIT 1`, tenantID).Scan(&rowID); err != nil {
		t.Fatalf("seed lookup: %v", err)
	}

	for _, op := range []string{
		`UPDATE audit_logs SET event='tampered' WHERE id=$1`,
		`DELETE FROM audit_logs WHERE id=$1`,
	} {
		_, err := h.pool.Exec(ctx, op, rowID)
		if err == nil {
			t.Fatalf("%s on audit_logs was accepted — immutability broken", op)
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("expected append-only rejection, got: %v", err)
		}
	}
}

// TestHS01_SecurityHeadersBaseline: the middleware source advertises the
// required baseline. Catches accidental deletion of HSTS / CSP / nosniff.
func TestHS01_SecurityHeadersBaseline(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	body, err := os.ReadFile(filepath.Join(root, "internal/middleware/middleware.go"))
	if err != nil {
		t.Skipf("middleware source not reachable: %v", err)
	}
	src := string(body)
	for _, want := range []string{
		"Strict-Transport-Security",
		"max-age=63072000",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
		"Permissions-Policy",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("middleware no longer sets %q", want)
		}
	}
}
