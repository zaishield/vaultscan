// Package auth's brute-force shield (HS-01). Per-IP failure tracking lives
// alongside the per-user lockout in users.RecordLogin — the two layers
// catch different attack shapes: per-user blocks credential stuffing at
// one email; per-IP blocks an attacker iterating many emails from one
// host.
package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BruteforceShield records login failures per IP and locks the IP once a
// configurable threshold (default 25 failures in 15 minutes) is crossed.
type BruteforceShield struct {
	pool      *pgxpool.Pool
	Threshold int           // failures
	Window    time.Duration // sliding window over which failures are counted
	LockFor   time.Duration // how long the IP stays locked once tripped
}

func NewBruteforceShield(pool *pgxpool.Pool) *BruteforceShield {
	return &BruteforceShield{
		pool:      pool,
		Threshold: 25,
		Window:    15 * time.Minute,
		LockFor:   15 * time.Minute,
	}
}

// RecordFailure stamps a failure row. Returns true if the IP just crossed
// the threshold and was therefore locked.
func (b *BruteforceShield) RecordFailure(ctx context.Context, ip net.IP, email string) (bool, error) {
	if ip == nil {
		return false, nil
	}
	if _, err := b.pool.Exec(ctx, `
		INSERT INTO auth_ip_failures(ip, email) VALUES ($1::inet, $2)`,
		ip.String(), nullIfEmpty(email)); err != nil {
		return false, err
	}
	var count int
	if err := b.pool.QueryRow(ctx, `
		SELECT count(*) FROM auth_ip_failures
		 WHERE ip = $1::inet AND occurred_at >= $2`,
		ip.String(), time.Now().UTC().Add(-b.Window)).Scan(&count); err != nil {
		return false, err
	}
	if count < b.Threshold {
		return false, nil
	}
	_, err := b.pool.Exec(ctx, `
		INSERT INTO auth_ip_lockouts(ip, locked_until, reason)
		VALUES ($1::inet, $2, $3)
		ON CONFLICT (ip) DO UPDATE
		   SET locked_until = GREATEST(auth_ip_lockouts.locked_until, EXCLUDED.locked_until),
		       reason       = EXCLUDED.reason,
		       locked_at    = now()`,
		ip.String(), time.Now().UTC().Add(b.LockFor),
		"failures="+itoa(count)+" within "+b.Window.String())
	return true, err
}

// IsLocked reports whether the IP is currently locked. Reads are cheap —
// the auth middleware calls this on every login attempt.
func (b *BruteforceShield) IsLocked(ctx context.Context, ip net.IP) (bool, time.Time, error) {
	if ip == nil {
		return false, time.Time{}, nil
	}
	var until time.Time
	err := b.pool.QueryRow(ctx, `
		SELECT locked_until FROM auth_ip_lockouts
		 WHERE ip=$1::inet AND locked_until > now()`, ip.String()).Scan(&until)
	if err != nil {
		// no row = not locked (pgx.ErrNoRows). We don't import pgx here.
		return false, time.Time{}, nil
	}
	return true, until, nil
}

// Unlock removes the lockout row. Operator-only.
func (b *BruteforceShield) Unlock(ctx context.Context, ip net.IP) error {
	if ip == nil {
		return errors.New("auth: cannot unlock nil ip")
	}
	_, err := b.pool.Exec(ctx,
		`DELETE FROM auth_ip_lockouts WHERE ip=$1::inet`, ip.String())
	return err
}

// SweepExpired removes lockouts whose timer has elapsed + prunes old
// failure rows. Designed for periodic cron invocation. Returns
// (lockoutsRemoved, failuresPruned).
func (b *BruteforceShield) SweepExpired(ctx context.Context) (int, int, error) {
	tag, err := b.pool.Exec(ctx,
		`DELETE FROM auth_ip_lockouts WHERE locked_until < now()`)
	if err != nil {
		return 0, 0, err
	}
	tag2, err := b.pool.Exec(ctx,
		`DELETE FROM auth_ip_failures WHERE occurred_at < now() - $1::interval`,
		(2 * b.Window).String())
	if err != nil {
		return int(tag.RowsAffected()), 0, err
	}
	return int(tag.RowsAffected()), int(tag2.RowsAffected()), nil
}

// IsPasswordCompromised checks the offline HIBP-style bucket table. The
// password's SHA-1 is split into a 5-char prefix + 35-char suffix; a
// matching row indicates the password appeared in a public breach corpus.
//
// Returns (compromised, seenCount, error).
func (b *BruteforceShield) IsPasswordCompromised(ctx context.Context, password string) (bool, int, error) {
	if len(password) == 0 {
		return false, 0, nil
	}
	h := sha1.Sum([]byte(password))
	hex := strings.ToUpper(hexEncode(h[:]))
	prefix := hex[:5]
	suffix := hex[5:]
	var seen int
	err := b.pool.QueryRow(ctx, `
		SELECT seen_count FROM compromised_password_buckets
		 WHERE bucket_prefix=$1 AND suffix=$2`, prefix, suffix).Scan(&seen)
	if err != nil {
		return false, 0, nil
	}
	return true, seen, nil
}

// LoadCompromisedBuckets ingests rows in the standard HIBP API shape:
//   <35-char-suffix>:<count>
// One file per 5-char prefix. The caller chooses how many files to ship.
func (b *BruteforceShield) LoadCompromisedBuckets(ctx context.Context, prefix string, body []byte) (int, error) {
	if len(prefix) != 5 {
		return 0, errors.New("auth: HIBP prefix must be 5 chars")
	}
	prefix = strings.ToUpper(prefix)
	loaded := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		suffix := strings.ToUpper(strings.TrimSpace(line[:colon]))
		if len(suffix) != 35 {
			continue
		}
		count := atoi(strings.TrimSpace(line[colon+1:]))
		_, _ = b.pool.Exec(ctx, `
			INSERT INTO compromised_password_buckets(bucket_prefix, suffix, seen_count)
			VALUES ($1, $2, $3)
			ON CONFLICT (bucket_prefix, suffix) DO UPDATE
			   SET seen_count = EXCLUDED.seen_count, loaded_at = now()`,
			prefix, suffix, count)
		loaded++
	}
	return loaded, nil
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
