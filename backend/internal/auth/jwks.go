// Package auth's JWT key management: RSA keypairs, rotation, and the
// JWKS endpoint shape that downstream services (CI gates, partner
// integrations, mobile clients) consume.
//
// Lifecycle:
//   active        — signs new tokens AND verifies. Exactly one row.
//   verify_only   — accepts tokens signed before rotation but does not
//                   sign new ones.
//   retired       — past the access-token max lifespan; ignored.
//
// Rotating: Rotate() inserts a new RSA-2048 keypair as active and
// flips the previous active row to verify_only. After
// access-token-lifespan + grace seconds, the cron-runner promotes
// verify_only → retired.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type KeyManager struct {
	pool *pgxpool.Pool
	kek  []byte // wraps private key at rest
}

func NewKeyManager(pool *pgxpool.Pool, kekBase64 string) (*KeyManager, error) {
	k, err := decodeB64(kekBase64)
	if err != nil {
		return nil, err
	}
	if len(k) < 32 {
		return nil, errors.New("jwks: KEK must decode to >=32 bytes")
	}
	return &KeyManager{pool: pool, kek: k[:32]}, nil
}

// Bootstrap ensures there's at least one active key. Idempotent —
// safe to call on every boot.
func (km *KeyManager) Bootstrap(ctx context.Context) (string, error) {
	var kid string
	err := km.pool.QueryRow(ctx,
		`SELECT kid FROM jwt_signing_keys WHERE status='active' LIMIT 1`).Scan(&kid)
	if err == nil {
		return kid, nil
	}
	// No active key — mint one in a fresh tx so we can satisfy the
	// jwt_signing_keys_single_active partial unique index.
	tx, err := km.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	newKid, err := km.insertActive(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return newKid, nil
}

// Rotate creates a new active key + flips the previous active row to
// verify_only. Returns the new kid. The caller (admin endpoint /
// scheduled rotation) typically follows up with a cron tick that
// retires verify_only rows older than the access-token lifespan.
func (km *KeyManager) Rotate(ctx context.Context) (string, error) {
	tx, err := km.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE jwt_signing_keys SET status='verify_only' WHERE status='active'`); err != nil {
		return "", err
	}
	kid, err := km.insertActive(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return kid, nil
}

// RetireOld promotes verify_only → retired for any key whose
// transition out of active happened more than `gracePeriod` ago.
// Designed for the cron-runner; gracePeriod should be at least the
// access-token max lifespan so no in-flight token is invalidated.
func (km *KeyManager) RetireOld(ctx context.Context, gracePeriod time.Duration) (int, error) {
	tag, err := km.pool.Exec(ctx, `
		UPDATE jwt_signing_keys
		   SET status = 'retired', retired_at = now()
		 WHERE status = 'verify_only'
		   AND created_at < now() - $1::interval`,
		gracePeriod.String())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ActivePrivateKey returns the kid + unwrapped private key the signer
// should use. Used by the JWT issuer (login + dev-token + token
// refresh paths).
func (km *KeyManager) ActivePrivateKey(ctx context.Context) (string, *rsa.PrivateKey, error) {
	var kid string
	var wrapped []byte
	err := km.pool.QueryRow(ctx, `
		SELECT kid, private_key_encrypted FROM jwt_signing_keys
		 WHERE status='active' LIMIT 1`).Scan(&kid, &wrapped)
	if err != nil {
		return "", nil, fmt.Errorf("jwks: no active key: %w", err)
	}
	raw, err := km.open(wrapped)
	if err != nil {
		return "", nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		return "", nil, err
	}
	return kid, key, nil
}

// PublicKeyByKID returns the verifying public key for a given kid.
// Verifies-only keys are accepted; retired keys are not — RS256 sig
// from a retired key fails verification.
func (km *KeyManager) PublicKeyByKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	var pemStr string
	err := km.pool.QueryRow(ctx, `
		SELECT public_key_pem FROM jwt_signing_keys
		 WHERE kid=$1 AND status IN ('active','verify_only')`, kid).Scan(&pemStr)
	if err != nil {
		return nil, errors.New("jwks: kid not known or retired")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("jwks: stored PEM unparseable")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwks: stored key is not RSA")
	}
	return rsaPub, nil
}

// JWKS is the shape of the /.well-known/jwks.json document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one entry. Only RS256 fields are populated (n, e, kty, kid,
// alg, use).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// PublicSet returns every active + verify_only key as a JWKS, ready to
// serve from /.well-known/jwks.json.
func (km *KeyManager) PublicSet(ctx context.Context) (*JWKS, error) {
	rows, err := km.pool.Query(ctx, `
		SELECT kid, public_key_pem FROM jwt_signing_keys
		 WHERE status IN ('active','verify_only') ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &JWKS{}
	for rows.Next() {
		var kid, pemStr string
		if err := rows.Scan(&kid, &pemStr); err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			continue
		}
		out.Keys = append(out.Keys, JWK{
			Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
		})
	}
	return out, rows.Err()
}

// ----- internals -----------------------------------------------------------

// pgxExecer is the minimal contract both pgxpool.Pool and pgx.Tx
// satisfy via their concrete Exec signature. We accept any pgx.Tx
// here so Rotate's outer transaction can include the INSERT.
type pgxExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// insertActive generates a new RSA-2048 keypair, encrypts the private
// key, and inserts a 'active' row via the supplied executor. Pulled
// out so Bootstrap and Rotate can share it.
func (km *KeyManager) insertActive(ctx context.Context, ex pgxExecer) (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	derPriv := x509.MarshalPKCS1PrivateKey(priv)
	wrapped, err := km.seal(derPriv)
	if err != nil {
		return "", err
	}
	derPub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derPub})

	kid := newKID()
	q := `
		INSERT INTO jwt_signing_keys(kid, alg, public_key_pem,
		    private_key_encrypted, private_key_kek_id, status)
		VALUES ($1, 'RS256', $2, $3, 'platform-kek-v1', 'active')`
	if _, err := ex.Exec(ctx, q, kid, string(pubPEM), wrapped); err != nil {
		return "", err
	}
	return kid, nil
}

func (km *KeyManager) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(km.kek)
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

func (km *KeyManager) open(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(km.kek)
	if err != nil {
		return nil, err
	}
	g, _ := cipher.NewGCM(block)
	ns := g.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("jwks: ciphertext too short")
	}
	return g.Open(nil, blob[:ns], blob[ns:], nil)
}

func newKID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	sum := sha256.Sum256(b)
	return "vs-" + hex.EncodeToString(sum[:8])
}

