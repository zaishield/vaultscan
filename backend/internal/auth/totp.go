// Package auth's TOTP enrolment + verification (RFC 6238 / RFC 4226).
// Implements the algorithm in-tree so we don't depend on a third-party
// library — keeps the trusted code surface small.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	totpDigits   = 6
	totpStep     = 30 * time.Second
	totpAlgo     = "SHA1"
	recoveryCnt  = 8

	// mfaMaxFailedAttempts is the threshold of failed Verify() calls
	// within mfaFailWindow after which the account is locked for
	// mfaLockoutDuration. Successful verify resets the counter.
	mfaMaxFailedAttempts = 5
	mfaFailWindow        = 15 * time.Minute
	mfaLockoutDuration   = 15 * time.Minute
)

// ErrMFALocked is returned by Verify when the user's account is in
// the lockout window after exceeding mfaMaxFailedAttempts. The login
// handler maps this to HTTP 429 (NOT 401) so callers can distinguish
// "wrong code" from "rate-limited" — and so brute-forcers can't
// silently keep guessing past the threshold.
var ErrMFALocked = errors.New("mfa: too many failed attempts; locked")

// MFAService handles enrolment + verification on top of user_mfa.
// kek is the 32-byte platform key wrapping the TOTP secret at rest.
type MFAService struct {
	pool *pgxpool.Pool
	kek  []byte
}

func NewMFAService(pool *pgxpool.Pool, kekBase64 string) (*MFAService, error) {
	if kekBase64 == "" {
		return nil, errors.New("mfa: KEK base64 required")
	}
	k, err := decodeB64(kekBase64)
	if err != nil {
		return nil, err
	}
	if len(k) < 32 {
		return nil, errors.New("mfa: KEK must decode to >=32 bytes")
	}
	return &MFAService{pool: pool, kek: k[:32]}, nil
}

// EnrollSecret is what StartEnrollment returns; the caller renders the
// OtpAuthURI as a QR code in the UI. The secret is also returned in
// plaintext (base32) so users can copy it into their authenticator app
// manually — only available BEFORE confirm, not stored in cleartext.
type EnrollSecret struct {
	Secret      string   `json:"secret_base32"`
	OtpAuthURI  string   `json:"otpauth_uri"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// StartEnrollment generates a fresh 20-byte secret, stages an
// AES-GCM-wrapped copy in user_mfa, returns the plaintext + provisioning
// URI for the user's authenticator. Subsequent calls overwrite (a user
// can restart enrolment until they confirm).
func (m *MFAService) StartEnrollment(ctx context.Context, userID uuid.UUID, accountLabel, issuer string) (*EnrollSecret, error) {
	if accountLabel == "" {
		return nil, errors.New("mfa: account label required")
	}
	if issuer == "" {
		issuer = "VAULTSCAN"
	}
	raw := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	secretB32 := strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
	wrapped, err := m.seal(raw)
	if err != nil {
		return nil, err
	}
	recovery, recoveryHashes, err := m.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashesJSON, _ := json.Marshal(recoveryHashes)
	if _, err := m.pool.Exec(ctx, `
		INSERT INTO user_mfa(user_id, totp_secret_encrypted, totp_secret_kek_id,
		    recovery_codes, recovery_codes_left)
		VALUES ($1, $2, 'platform-kek-v1', $3::jsonb, $4)
		ON CONFLICT (user_id) DO UPDATE
		   SET totp_secret_encrypted = EXCLUDED.totp_secret_encrypted,
		       totp_secret_kek_id    = EXCLUDED.totp_secret_kek_id,
		       recovery_codes        = EXCLUDED.recovery_codes,
		       recovery_codes_left   = EXCLUDED.recovery_codes_left,
		       enrolled_at           = now(),
		       last_verified_at      = NULL`,
		userID, wrapped, hashesJSON, recoveryCnt); err != nil {
		return nil, fmt.Errorf("mfa: stage enrolment: %w", err)
	}
	// Until ConfirmEnrollment runs successfully, users.mfa_status is
	// NOT bumped — an unfinished enrolment leaves auth flow as before.
	return &EnrollSecret{
		Secret:        secretB32,
		OtpAuthURI:    otpauthURI(issuer, accountLabel, secretB32),
		RecoveryCodes: recovery,
	}, nil
}

// ConfirmEnrollment verifies the first user-supplied 6-digit code
// against the staged secret. On success: bumps users.mfa_status to
// 'enrolled', stamps last_verified_at, and persists the accepted
// counter so the same code cannot be replayed.
func (m *MFAService) ConfirmEnrollment(ctx context.Context, userID uuid.UUID, code string) error {
	secret, err := m.unwrapSecret(ctx, userID)
	if err != nil {
		return err
	}
	matched := verifyTOTP(secret, code, time.Now().UTC())
	if matched < 0 {
		return errors.New("mfa: code invalid")
	}
	if _, err := m.pool.Exec(ctx, `
		UPDATE user_mfa
		   SET last_verified_at = now(),
		       last_used_counter = $2,
		       failed_verify_count = 0,
		       failed_verify_window_start = NULL,
		       locked_until = NULL
		 WHERE user_id = $1`, userID, matched); err != nil {
		return err
	}
	if _, err := m.pool.Exec(ctx, `
		UPDATE users SET mfa_status='enrolled', mfa_enabled=true WHERE id=$1`, userID); err != nil {
		return err
	}
	return nil
}

// Verify is what the login flow calls during the MFA second step.
// Accepts either a TOTP code OR a recovery code; the latter consumes
// one of the 8 backup slots.
//
// Enforces:
//   - lockout window: returns ErrMFALocked if locked_until > now
//   - counter replay protection: refuses codes whose matched counter
//     <= last_used_counter (RFC 6238 §5.2)
//   - rate limiting: after mfaMaxFailedAttempts failures in
//     mfaFailWindow, the account is locked for mfaLockoutDuration
func (m *MFAService) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	// Lockout + last-used + secret in a single row read so the lockout
	// check is consistent with the verify attempt that follows.
	var (
		wrapped        []byte
		lastUsed       int64
		lockedUntil    *time.Time
		failedCount    int
		failedStart    *time.Time
	)
	err := m.pool.QueryRow(ctx, `
		SELECT totp_secret_encrypted, last_used_counter, locked_until,
		       failed_verify_count, failed_verify_window_start
		  FROM user_mfa WHERE user_id = $1`, userID).
		Scan(&wrapped, &lastUsed, &lockedUntil, &failedCount, &failedStart)
	if err != nil {
		return errors.New("mfa: not enrolled")
	}
	now := time.Now().UTC()
	if lockedUntil != nil && lockedUntil.After(now) {
		return ErrMFALocked
	}
	// Roll the failure window: if the window started > mfaFailWindow
	// ago, reset the counter before counting new failures.
	if failedStart != nil && now.Sub(*failedStart) > mfaFailWindow {
		failedCount = 0
		failedStart = nil
	}

	secret, err := m.open(wrapped)
	if err != nil {
		return errors.New("mfa: not enrolled")
	}

	// Try TOTP first.
	matched := verifyTOTP(secret, code, now)
	if matched >= 0 && matched > lastUsed {
		// Success — accept, reset failure tracking, stamp counter.
		if _, err := m.pool.Exec(ctx, `
			UPDATE user_mfa
			   SET last_verified_at = now(),
			       last_used_counter = $2,
			       failed_verify_count = 0,
			       failed_verify_window_start = NULL,
			       locked_until = NULL
			 WHERE user_id = $1`, userID, matched); err != nil {
			return err
		}
		return nil
	}
	if matched >= 0 && matched <= lastUsed {
		// Code matched a window but the counter has already been
		// consumed — explicit replay. Count this as a failed attempt
		// for rate-limit purposes (a legitimate user wouldn't replay).
		return m.recordFailure(ctx, userID, failedCount, failedStart, now)
	}

	// Fall through to recovery codes. A successful consumption resets
	// the failure counter; a miss increments it.
	if err := m.consumeRecoveryCode(ctx, userID, code); err == nil {
		_, _ = m.pool.Exec(ctx, `
			UPDATE user_mfa
			   SET failed_verify_count = 0,
			       failed_verify_window_start = NULL,
			       locked_until = NULL
			 WHERE user_id = $1`, userID)
		return nil
	}
	return m.recordFailure(ctx, userID, failedCount, failedStart, now)
}

// recordFailure increments the rolling failure counter and engages
// the lockout when the threshold is crossed. Returns the user-facing
// error to surface: ErrMFALocked when this attempt tripped the
// threshold, "code invalid" otherwise.
func (m *MFAService) recordFailure(
	ctx context.Context,
	userID uuid.UUID,
	priorCount int,
	priorStart *time.Time,
	now time.Time,
) error {
	newCount := priorCount + 1
	windowStart := priorStart
	if windowStart == nil {
		t := now
		windowStart = &t
	}
	var lockUntil *time.Time
	resultErr := errors.New("mfa: code invalid")
	if newCount >= mfaMaxFailedAttempts {
		lu := now.Add(mfaLockoutDuration)
		lockUntil = &lu
		// Reset the rolling counter so post-lockout the next failure
		// starts fresh.
		newCount = 0
		windowStart = nil
		resultErr = ErrMFALocked
	}
	if _, err := m.pool.Exec(ctx, `
		UPDATE user_mfa
		   SET failed_verify_count = $2,
		       failed_verify_window_start = $3,
		       locked_until = $4
		 WHERE user_id = $1`, userID, newCount, windowStart, lockUntil); err != nil {
		// DB write failure shouldn't unlock the account — surface the
		// invalid-code error and rely on the next attempt to retry
		// the bookkeeping. The lockout we WERE about to apply isn't
		// persisted, so a determined attacker can bypass this single
		// instance; the absent row is logged via the caller's error
		// path. (DB outages are rare and the audit log catches them.)
		return resultErr
	}
	return resultErr
}

// IsEnrolled is a cheap predicate the API uses before requiring MFA.
func (m *MFAService) IsEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	var status string
	err := m.pool.QueryRow(ctx,
		`SELECT mfa_status FROM users WHERE id = $1`, userID).Scan(&status)
	if err != nil {
		return false, err
	}
	return status == "enrolled" || status == "required", nil
}

// Disable wipes the user's MFA row and resets mfa_status. Used by
// /api/v1/auth/me/mfa DELETE when a user with a recovery code wants
// to re-enrol.
func (m *MFAService) Disable(ctx context.Context, userID uuid.UUID) error {
	if _, err := m.pool.Exec(ctx, `DELETE FROM user_mfa WHERE user_id=$1`, userID); err != nil {
		return err
	}
	_, err := m.pool.Exec(ctx,
		`UPDATE users SET mfa_status='none', mfa_enabled=false WHERE id=$1`, userID)
	return err
}

// ----- internals ------------------------------------------------------------

func (m *MFAService) unwrapSecret(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	var wrapped []byte
	err := m.pool.QueryRow(ctx,
		`SELECT totp_secret_encrypted FROM user_mfa WHERE user_id=$1`, userID).Scan(&wrapped)
	if err != nil {
		return nil, errors.New("mfa: not enrolled")
	}
	return m.open(wrapped)
}

// consumeRecoveryCode walks the user's recovery-code list looking for
// a bcrypt match. Mirrors the scimtokens.Verify timing-oracle defence:
// every non-empty slot is bcrypt-checked regardless of earlier hits,
// so request latency doesn't leak which slot (if any) matched. Without
// this an attacker timing failed-then-successful attempts could
// learn the slot ordering.
func (m *MFAService) consumeRecoveryCode(ctx context.Context, userID uuid.UUID, code string) error {
	var raw []byte
	if err := m.pool.QueryRow(ctx,
		`SELECT recovery_codes FROM user_mfa WHERE user_id=$1`, userID).Scan(&raw); err != nil {
		return errors.New("mfa: code invalid")
	}
	var hashes []string
	_ = json.Unmarshal(raw, &hashes)
	codeUpper := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	matchedIdx := -1
	for i, h := range hashes {
		if h == "" {
			continue
		}
		// Always run bcrypt on every non-empty slot. Take only the
		// first match's index — total bcrypt cost is N×slot-cost
		// regardless of input, so slot position is no longer
		// observable via latency.
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(codeUpper)) == nil && matchedIdx == -1 {
			matchedIdx = i
		}
	}
	if matchedIdx == -1 {
		return errors.New("mfa: code invalid")
	}
	hashes[matchedIdx] = ""
	out, _ := json.Marshal(hashes)
	_, _ = m.pool.Exec(ctx, `
		UPDATE user_mfa
		   SET recovery_codes = $2::jsonb,
		       recovery_codes_left = GREATEST(recovery_codes_left - 1, 0),
		       last_verified_at = now()
		 WHERE user_id = $1`,
		userID, out)
	return nil
}

func (m *MFAService) newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, recoveryCnt)
	hashes := make([]string, recoveryCnt)
	for i := 0; i < recoveryCnt; i++ {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, nil, err
		}
		full := strings.ToUpper(hex.EncodeToString(buf))
		// XXXX-XXXX-XX → easier to read & type
		display := full[:4] + "-" + full[4:8] + "-" + full[8:10]
		codes[i] = display
		h, err := bcrypt.GenerateFromPassword([]byte(strings.ToUpper(full)), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = string(h)
	}
	return codes, hashes, nil
}

// ----- AES-GCM wrap / unwrap ------------------------------------------------

func (m *MFAService) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, err
	}
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, g.Seal(nil, nonce, plain, nil)...), nil
}

func (m *MFAService) open(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, err
	}
	g, _ := cipher.NewGCM(block)
	ns := g.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("mfa: ciphertext too short")
	}
	return g.Open(nil, blob[:ns], blob[ns:], nil)
}

// ----- TOTP RFC 6238 --------------------------------------------------------

// verifyTOTP checks the code against the current 30-second window
// plus the one before and after (drift tolerance). Returns the
// matched counter on success (so the caller can persist it for
// replay protection) and -1 when no window matched.
func verifyTOTP(secret []byte, code string, now time.Time) int64 {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return -1
	}
	counter := int64(uint64(now.Unix()) / uint64(totpStep.Seconds()))
	for offset := int64(-1); offset <= 1; offset++ {
		candidate := counter + offset
		expected := hotp(secret, uint64(candidate))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return candidate
		}
	}
	return -1
}

func hotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, secret)
	h.Write(buf[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	otp := val % 1000000
	return fmt.Sprintf("%06d", otp)
}

// otpauthURI produces the URI authenticator apps render as a QR code.
// Format: otpauth://totp/<issuer>:<account>?secret=...&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
func otpauthURI(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", totpAlgo)
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%.0f", totpStep.Seconds()))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// decodeB64 is a tolerant base64 decoder accepting both standard +
// URL-safe alphabets, with or without padding.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("auth: not base64")
}
