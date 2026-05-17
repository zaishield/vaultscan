// cdn.go — CDN-signed URL rewriter for partner brand assets.
//
// Before this batch, partner_brand_assets.storage_url pointed at the
// evidence vault and every portal page-load required a fresh signed-
// download round-trip through the API. That's fine for tens of
// requests; at hundreds-of-thousands of page-loads/day the API
// becomes the bottleneck for serving static logos.
//
// This file implements two CDN signing strategies. Operators pick
// one via VAULTSCAN_CDN_MODE:
//
//	disabled    — pass storage_url through unchanged (default;
//	              preserves legacy behaviour)
//	prefix      — naive prefix rewrite: replace the storage backend
//	              scheme + host with VAULTSCAN_CDN_PUBLIC_BASE.
//	              Suitable for Cloudflare in "everything public"
//	              mode where the CDN sits in front of a public R2
//	              bucket. No signing — anyone with the URL can
//	              fetch.
//	cloudfront  — AWS CloudFront signed-URL (canned-policy form,
//	              RSA-SHA1, query-string signature). Requires a
//	              CloudFront key pair (key ID + RSA private key).
//	              Expires per the configured TTL.
//
// The asset list endpoint applies the rewrite before returning the
// rows so the portal gets ready-to-use URLs.

package branding

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 — CloudFront mandates SHA-1 for signed URLs
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// CDNMode enumerates the supported signing strategies.
type CDNMode string

const (
	CDNModeDisabled   CDNMode = "disabled"
	CDNModePrefix     CDNMode = "prefix"
	CDNModeCloudFront CDNMode = "cloudfront"
)

// CDNConfig is the operator-facing knob bundle. The branding service
// reads this at construction time and applies it to every storage_url
// it returns. Zero value = CDNModeDisabled.
type CDNConfig struct {
	Mode CDNMode

	// PublicBase is the CDN's externally-resolvable URL prefix
	// (e.g. "https://cdn.vaultscan.example.com"). Used by both
	// "prefix" and "cloudfront" modes — for the latter it forms the
	// scheme + host portion of the signed URL.
	PublicBase string

	// SignedTTL is how long a CloudFront signed URL stays valid.
	// Long-enough to absorb portal page navigation, short enough
	// that a leaked URL can't be passed around. 1h is the default.
	SignedTTL time.Duration

	// CloudFront-only.
	KeyPairID  string
	PrivateKey *rsa.PrivateKey
}

// LoadCloudFrontKey parses an RSA private key from PEM (PKCS#1 or
// PKCS#8). CloudFront-issued private keys are PKCS#1; modern key
// generators emit PKCS#8. Both shapes are handled here so operators
// don't need to convert.
func LoadCloudFrontKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("branding: PEM decode produced no block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaK, ok := any.(*rsa.PrivateKey); ok {
			return rsaK, nil
		}
		return nil, errors.New("branding: PKCS#8 key is not RSA")
	}
	return nil, errors.New("branding: PEM is neither PKCS#1 nor PKCS#8 RSA")
}

// SetCDNConfig wires CDN signing on the AssetService. Production
// builds call this from cmd/api after loading the keys from config;
// dev leaves it unset.
func (s *AssetService) SetCDNConfig(cfg CDNConfig) {
	if cfg.SignedTTL == 0 {
		cfg.SignedTTL = time.Hour
	}
	if cfg.Mode == "" {
		cfg.Mode = CDNModeDisabled
	}
	s.cdn = &cfg
}

// rewriteStorageURL returns the CDN-fronted URL for a stored asset.
// Falls through to the original URL when CDN is disabled or the
// config is incomplete (defence in depth: a misconfigured CDN
// shouldn't break the portal — it just degrades to direct fetch).
func (s *AssetService) rewriteStorageURL(storageURL string) string {
	if s == nil || s.cdn == nil || s.cdn.Mode == CDNModeDisabled || s.cdn.PublicBase == "" {
		return storageURL
	}
	switch s.cdn.Mode {
	case CDNModePrefix:
		return prefixRewrite(s.cdn.PublicBase, storageURL)
	case CDNModeCloudFront:
		if s.cdn.KeyPairID == "" || s.cdn.PrivateKey == nil {
			return storageURL
		}
		signed, err := signCloudFrontCanned(
			s.cdn.PublicBase, storageURL,
			s.cdn.KeyPairID, s.cdn.PrivateKey,
			time.Now().Add(s.cdn.SignedTTL),
		)
		if err != nil {
			return storageURL
		}
		return signed
	}
	return storageURL
}

// prefixRewrite swaps the scheme + host of the input URL with the
// public CDN base. Path + query are preserved. Inputs that don't
// look like URLs are returned unchanged so a misconfigured row
// doesn't break the page.
func prefixRewrite(publicBase, storageURL string) string {
	u, err := url.Parse(storageURL)
	if err != nil || u.Path == "" {
		return storageURL
	}
	base, err := url.Parse(publicBase)
	if err != nil {
		return storageURL
	}
	u.Scheme = base.Scheme
	u.Host = base.Host
	// If publicBase carried a path prefix (e.g. .../assets), prepend it.
	if base.Path != "" && base.Path != "/" {
		u.Path = strings.TrimRight(base.Path, "/") + u.Path
	}
	return u.String()
}

// signCloudFrontCanned generates a CloudFront signed URL using the
// canned-policy form (single fixed expiry, no IP restriction). This
// is the simpler of CloudFront's two signing modes — it produces a
// URL like:
//
//	https://cdn.../<path>?Expires=N&Signature=...&Key-Pair-Id=K
//
// Reference: AWS CloudFront Developer Guide, "Creating a signed URL
// using a canned policy".
//
// The policy JSON is exactly:
//
//	{"Statement":[{"Resource":"<resource>","Condition":{"DateLessThan":{"AWS:EpochTime":<expiry>}}}]}
//
// Signed with RSA-SHA1 (CloudFront's only supported algorithm for
// canned policies as of 2026). The signature is base64-encoded with
// the CloudFront URL-safe variant: '+' → '-', '=' → '_', '/' → '~'.
func signCloudFrontCanned(publicBase, storageURL, keyID string,
	priv *rsa.PrivateKey, expiry time.Time) (string, error) {

	// Build the resource URL — that's publicBase + path of storageURL.
	resource := prefixRewrite(publicBase, storageURL)
	if resource == storageURL {
		// prefix rewrite failed; signature couldn't be applied to
		// the right resource string. Refuse rather than sign a
		// wrong resource.
		return "", errors.New("cloudfront: prefix rewrite failed")
	}
	exp := expiry.Unix()
	policy := fmt.Sprintf(
		`{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%d}}}]}`,
		resource, exp)

	h := sha1.New() // #nosec G401 — CloudFront mandates SHA-1
	h.Write([]byte(policy))
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA1, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("cloudfront: sign: %w", err)
	}

	// CloudFront's URL-safe base64 substitutions.
	enc := func(b []byte) string {
		s := base64.StdEncoding.EncodeToString(b)
		s = strings.ReplaceAll(s, "+", "-")
		s = strings.ReplaceAll(s, "=", "_")
		s = strings.ReplaceAll(s, "/", "~")
		return s
	}

	u, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("Expires", fmt.Sprintf("%d", exp))
	q.Set("Signature", enc(sig))
	q.Set("Key-Pair-Id", keyID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
