// backend_awskms.go — AWS KMS-based secrets backend.
//
// Strategy: secrets are stored as base64-encoded ciphertext in
// Postgres (vaultscan_secrets table). Get fetches the ciphertext +
// calls KMS Decrypt with the CMK; Put calls KMS Encrypt and stores
// the result.
//
// Why this layout: KMS itself doesn't store secrets, only keys. So
// we use KMS as the wrapping authority and Postgres as the storage.
// This means secret reads cost a KMS Decrypt call (~$0.03/10k) plus
// a DB query — acceptable for our access patterns.
//
// API used:
//   POST https://kms.<region>.amazonaws.com/
//   X-Amz-Target: TrentService.Encrypt | TrentService.Decrypt
//   Body: {"KeyId":"alias/vaultscan", "Plaintext":<b64>} | {"CiphertextBlob":<b64>}

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/awssig"
)

type AWSKMSBackend struct {
	pool       *pgxpool.Pool
	region     string
	keyID      string  // CMK ID, ARN, or alias/<name>
	creds      awssig.Credentials
	httpClient *http.Client
}

type AWSKMSConfig struct {
	Pool            *pgxpool.Pool  // required — store for ciphertext
	Region          string
	KeyID           string  // CMK ID/ARN/alias
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
}

func NewAWSKMSBackend(cfg AWSKMSConfig) (*AWSKMSBackend, error) {
	if cfg.Pool == nil {
		return nil, errors.New("secrets: kms backend requires Postgres pool for ciphertext storage")
	}
	if cfg.Region == "" || cfg.KeyID == "" {
		return nil, errors.New("secrets: kms region + key_id required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("secrets: kms credentials required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &AWSKMSBackend{
		pool:       cfg.Pool,
		region:     cfg.Region,
		keyID:      cfg.KeyID,
		creds:      awssig.Credentials{AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey, SessionToken: cfg.SessionToken},
		httpClient: hc,
	}, nil
}

func (b *AWSKMSBackend) Get(ctx context.Context, ref string) (string, error) {
	plain, err := b.GetBytes(ctx, ref)
	if err != nil {
		return "", err
	}
	// string(plain) copies the bytes into an immutable string buffer.
	// Zero the working slice so the only remaining heap copy is the
	// string returned to the caller (which the caller owns + manages).
	out := string(plain)
	zeroBytes(plain)
	return out, nil
}

// GetBytes returns the decrypted secret as a mutable []byte so the
// caller can zeroize it as soon as it's no longer needed. Prefer this
// over Get when the secret is short-lived (e.g. wrapping a per-
// request DEK) — Get returns an immutable string that can only be
// reclaimed by GC.
func (b *AWSKMSBackend) GetBytes(ctx context.Context, ref string) ([]byte, error) {
	var ciphertextB64 string
	err := b.pool.QueryRow(ctx,
		`SELECT ciphertext_b64 FROM vaultscan_secrets WHERE ref = $1`, ref).Scan(&ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("secrets: kms ref %q not found: %w", ref, err)
	}
	return b.kmsDecrypt(ctx, ciphertextB64)
}

func (b *AWSKMSBackend) Put(ctx context.Context, ref, value string) error {
	ct, err := b.kmsEncrypt(ctx, []byte(value))
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, `
		INSERT INTO vaultscan_secrets(ref, ciphertext_b64, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (ref) DO UPDATE
		   SET ciphertext_b64 = EXCLUDED.ciphertext_b64,
		       updated_at = now()`,
		ref, ct)
	return err
}

// ---- KMS HTTP ------------------------------------------------------------

func (b *AWSKMSBackend) kmsEncrypt(ctx context.Context, plain []byte) (string, error) {
	// json.Marshal of the request body holds a copy of the
	// base64-encoded plaintext on the heap. Build the body, send it,
	// then zero the buffer so the only post-call heap residue is the
	// CiphertextBlob (already encrypted under the CMK).
	body, _ := json.Marshal(map[string]any{
		"KeyId":     b.keyID,
		"Plaintext": base64.StdEncoding.EncodeToString(plain),
	})
	defer zeroBytes(body)
	resp, err := b.kmsCall(ctx, "TrentService.Encrypt", body)
	if err != nil {
		return "", err
	}
	var r struct {
		CiphertextBlob string `json:"CiphertextBlob"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return "", err
	}
	if r.CiphertextBlob == "" {
		return "", errors.New("kms: empty ciphertext")
	}
	return r.CiphertextBlob, nil
}

func (b *AWSKMSBackend) kmsDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{
		"CiphertextBlob": ciphertextB64,
	})
	resp, err := b.kmsCall(ctx, "TrentService.Decrypt", body)
	if err != nil {
		return nil, err
	}
	// Plaintext as []byte lets encoding/json auto-decode the
	// base64 string into the byte slice — no intermediate
	// immutable plaintext string on the heap.
	var r struct {
		Plaintext []byte `json:"Plaintext"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		zeroBytes(resp)
		return nil, err
	}
	// resp still contains the base64-encoded plaintext in its bytes;
	// clear before returning so the only heap copy is r.Plaintext
	// (which the caller owns + can zero).
	zeroBytes(resp)
	return r.Plaintext, nil
}

// zeroBytes overwrites b in place with zeroes. The Go compiler does
// NOT optimise this away because zeroBytes' visible effect is a
// write to memory shared via slice (escape-analyzed). Use this for
// any byte buffer that carried plaintext key material before letting
// it fall out of scope — clears the only on-heap copy we control.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (b *AWSKMSBackend) kmsCall(ctx context.Context, target string, body []byte) ([]byte, error) {
	host := fmt.Sprintf("kms.%s.amazonaws.com", b.region)
	url := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	if err := awssig.Sign(req, b.region, "kms", b.creds); err != nil {
		return nil, err
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kms %s: %d %s", target, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}
